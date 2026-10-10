import assert from "node:assert/strict";
import express from "express";
import { registerWorkerPlatform } from "./worker-platform.js";

const user="00000000-0000-4000-8000-000000000001";
const other="00000000-0000-4000-8000-000000000002";
process.env.WORKER_TOKEN="TEST_WORKER_TOKEN_LONG";
let snapshotWrites=0;
let current={ user_id:user,provisioning_status:"ready",credential_version:2,snapshot_version:2,
  heartbeat_at:new Date(),open_count:0,desired_state:"paused" };
let changed;
async function query(sql,values) {
  if(sql.startsWith("select credential_version"))return {rows:[{credential_version:2}]};
  if(sql.includes("insert into client_bot_snapshots")){snapshotWrites++;return {rows:[],rowCount:1}};
  if(sql.startsWith("update client_bot_setups")){changed=values;return {rows:[current],rowCount:1}};
  if(sql.includes("where s.user_id=$1"))return {rows:values[0]===user?[current]:[]};
  if(sql.includes("join users"))return {rows:[]};
  throw new Error("Unexpected SQL");
}
const app=express();app.use(express.json());
const auth=(req,res,next)=>{if(req.headers['x-test-user']!==user&&req.headers['x-test-user']!==other)return res.sendStatus(401);req.userId=req.headers['x-test-user'];next()};
const paid=(req,res,next)=>req.headers['x-test-paid']==='yes'?next():res.sendStatus(403);
registerWorkerPlatform({app,query,auth,requireActivePayment:paid,asyncRoute:fn=>(req,res,next)=>Promise.resolve(fn(req,res)).catch(next)});
app.use((err,req,res,next)=>res.status(400).json({error:"Invalid payload"}));
const server=app.listen(0,'127.0.0.1');await new Promise(resolve=>server.once('listening',resolve));
const base=`http://127.0.0.1:${server.address().port}`;
async function request(path,body,headers={}) {
 const response=await fetch(base+path,{method:body?'POST':'GET',headers:{'Content-Type':'application/json','x-test-user':user,'x-test-paid':'yes',...headers},body:body?JSON.stringify(body):undefined});
 const raw=await response.text();let data;try{data=JSON.parse(raw)}catch{}return {status:response.status,data};
}
try {
 assert.equal((await request('/worker/accounts')).status,401);
 assert.equal((await request('/worker/accounts',null,{'x-worker-token':process.env.WORKER_TOKEN})).status,200);
 assert.equal((await request('/bot/overview',null,{'x-test-user':''})).status,401);
 assert.equal((await request('/bot/overview',null,{'x-test-paid':'no'})).status,403);
 assert.equal((await request('/bot/overview',null,{'x-test-user':other})).data.bot,null);
 const account={userId:user,credentialVersion:1,actualState:'paused',openPositions:[],recentClosedTrades:[]};
 const stale=await request('/worker/heartbeat',{workerId:'pilot',accounts:[account]},{'x-worker-token':process.env.WORKER_TOKEN});
 assert.equal(stale.data.accepted,0);assert.equal(snapshotWrites,0);
 const fresh=await request('/worker/heartbeat',{workerId:'pilot',accounts:[{...account,credentialVersion:2}]},{'x-worker-token':process.env.WORKER_TOKEN});
 assert.equal(fresh.data.accepted,1);assert.equal(snapshotWrites,1);
 assert.equal((await request('/bot/control',{action:'start',userId:other})).status,200);
 assert.equal(changed[0],user,'Body userId must never override authenticated identity');
 current={...current,heartbeat_at:new Date(0)};
 assert.equal((await request('/bot/control',{action:'start'})).status,409);
 assert.equal((await request('/bot/control',{action:'pause'})).status,200);
 current={...current,heartbeat_at:new Date(),snapshot_version:1};
 assert.equal((await request('/bot/control',{action:'start'})).status,409);
 current={...current,snapshot_version:2,open_count:1};
 assert.equal((await request('/bot/control',{action:'stop'})).status,409);
 assert.equal((await request('/bot/control',{action:'pause'})).status,200);
 assert.equal((await request('/worker/heartbeat',{workerId:'pilot',accounts:[{...account,userId:'invalid'}]},{'x-worker-token':process.env.WORKER_TOKEN})).status,400);
 console.log('PASS: worker authentication, payment gates, tenant scoping, stale credential rejection, heartbeat freshness, safe pause/stop and malformed payloads. Mock database only.');
}finally{server.closeAllConnections();await new Promise(resolve=>server.close(resolve));}
