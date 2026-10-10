import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import express from 'express';
import { verifyViaWorker } from './binance-verification.js';
import { registerWorkerPlatform } from './worker-platform.js';

const { publicKey, privateKey } = crypto.generateKeyPairSync('rsa', { modulusLength:3072 });
process.env.WORKER_PUBLIC_KEY_B64 = Buffer.from(publicKey.export({type:'spki',format:'pem'})).toString('base64');
process.env.WORKER_TOKEN = 'test-worker-token';
let job, cooldown=0, deletes=0;
const now=Math.max(Date.now(),1791665443442);
async function query(sql, values) {
  if (sql.includes('system_migrations')) return {rows:[{details:{retryAt:cooldown}}]};
  if (sql.startsWith('insert into binance_verification_jobs')) { job={id:values[0],ciphertext:values[1],status:'pending'}; return {rows:[],rowCount:1}; }
  if (sql.startsWith('select result')) return {rows:job ? [{result:job.result}] : []};
  if (sql.includes("set status='processing'")) { if(job?.status!=='pending') return {rows:[]}; job.status='processing'; return {rows:[{id:job.id,ciphertext:job.ciphertext}]}; }
  if (sql.includes("set status='done'")) { if(job?.status==='processing' && values[0]===job.id) {job.status='done';job.result=JSON.parse(values[1]);job.ciphertext=null;} return {rows:[]}; }
  if (sql.startsWith('delete')) { if(values) {job=null;deletes++;} return {rows:[]}; }
  throw Error('Unexpected query');
}
const app=express();app.use(express.json());
registerWorkerPlatform({app,query,auth:(req,res,next)=>next(),requireActivePayment:(req,res,next)=>next(),asyncRoute:fn=>(req,res,next)=>Promise.resolve(fn(req,res)).catch(next)});
app.use((err,req,res,next)=>res.status(400).json({error:'Invalid request'}));
const server=app.listen(0,'127.0.0.1');
await new Promise(resolve=>server.once('listening',resolve));
const base=`http://127.0.0.1:${server.address().port}`;
const request=(path,body,authorized=true)=>fetch(base+path,{method:body?'POST':'GET',headers:{'Content-Type':'application/json',...(authorized?{'X-Worker-Token':process.env.WORKER_TOKEN}:{})},body:body?JSON.stringify(body):undefined});
try {
  assert.equal((await request('/worker/verification',null,false)).status,401);
  cooldown=now+60000;
  assert.equal((await verifyViaWorker(query,'fake-key','fake-secret',{now:()=>now})).status,'failed');
  assert.equal(job,undefined,'Active ban must prevent queuing any provider check');
  cooldown=0;
  const verified=await verifyViaWorker(query,'fake-key','fake-secret',{now:()=>now,attempts:1,wait:async()=>{
    assert.ok(!job.ciphertext.includes('fake-secret'));
    const claimed=(await (await request('/worker/verification')).json()).job;
    const decoded=JSON.parse(crypto.privateDecrypt({key:privateKey,oaepHash:'sha256',padding:crypto.constants.RSA_PKCS1_OAEP_PADDING},Buffer.from(claimed.ciphertext,'base64')).toString());
    assert.equal(decoded.apiSecret,'fake-secret');
    assert.equal((await (await request('/worker/verification')).json()).job,null,'Claim once only');
    assert.equal((await request(`/worker/verification/${claimed.id}`,{status:'verified',message:'Verified'},false)).status,401);
    await request(`/worker/verification/${claimed.id}`,{status:'verified',message:'Verified'});
    assert.equal(job.ciphertext,null,'Erase transient keys after completion');
  }});
  assert.equal(verified.status,'verified');
  assert.equal(job,null);
  assert.equal((await verifyViaWorker(query,'fake-key','fake-secret',{now:()=>now,attempts:1,wait:async()=>{}})).status,'failed');
  assert.equal(job,null,'Erase transient keys on timeout');
  assert.equal((await request('/worker/verification/bad',{status:'verified',message:'test'})).status,400);
  assert.equal(deletes,2);
  console.log('PASS: authenticated Oracle verification, encrypted transport, cooldown, single claim, completion and timeout cleanup. No exchange requests.');
} finally { server.closeAllConnections();await new Promise(resolve=>server.close(resolve)); }
