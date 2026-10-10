import assert from "node:assert/strict";
import crypto from "node:crypto";
import express from "express";
import { registerCredentialSettings, checkReplacement, connectionStatus } from "./credential-settings.js";

const { publicKey, privateKey } = crypto.generateKeyPairSync("rsa", { modulusLength: 3072 });
process.env.WORKER_PUBLIC_KEY_B64 = Buffer.from(publicKey.export({type:"spki",format:"pem"})).toString("base64");
const rows = new Map();
let verifications = 0;
let race = false;
const id = i => `00000000-0000-4000-8000-${String(i).padStart(12,"0")}`;
const fresh = () => ({ desired_state:"paused", actual_state:"paused", heartbeat_at:new Date(), open_count:0, credential_version:1, snapshot_version:1 });
async function query(sql, values) {
  const user = values[0];
  let row = rows.get(user);
  if (sql.startsWith("insert into client_bot_setups")) {
    if (!row) { row = {user_id:user,desired_state:"paused",credential_version:0}; rows.set(user,row); }
  } else if (sql.startsWith("select s.*")) {
    return {rows:row ? [{...row}] : []};
  } else if (sql.startsWith("insert into client_bot_credentials")) {
    row[sql.includes("binance_ciphertext") ? "binance_ciphertext" : "coinalyze_ciphertext"] = values[1];
    row.credential_version++;
  } else if (sql.startsWith("update client_bot_setups set")) {
    const provider = sql.includes("binance_status") ? "binance" : "coinalyze";
    Object.assign(row,{[`${provider}_status`]:"verified",desired_state:"paused",provisioning_status:"pending"});
    // Real returning * contains no credentials: credentials are in a separate table.
    return {rows:[{user_id:user,[`${provider}_status`]:"verified",desired_state:"paused"}]};
  } else throw new Error("Unrecognized test query");
  return {rows:[]};
}
const app = express();
app.use(express.json());
const auth = (req,res,next) => { req.userId=req.headers["x-test-user"]; if(!req.userId)return res.sendStatus(401); next(); };
const paid = (req,res,next) => req.headers["x-test-paid"]==="yes" ? next() : res.sendStatus(403);
const verify = async key => {
  verifications++;
  if (race) rows.get(id(1)).desired_state="running";
  return key.startsWith("invalid") ? {status:"failed",message:"Invalid replacement key"} : {status:"verified"};
};
registerCredentialSettings({ app,query,transaction:fn=>fn({query}),auth,requireActivePayment:paid,
  asyncRoute:fn=>(req,res,next)=>Promise.resolve(fn(req,res)).catch(next),
  verifyBinanceFutures:verify,verifyCoinalyze:verify });
app.use((err,req,res,next)=>res.status(err.status||400).json({error:err.message}));
const server=app.listen(0,"127.0.0.1");
await new Promise(resolve=>server.once("listening",resolve));
const base=`http://127.0.0.1:${server.address().port}`;
async function request(path,user,body,extra={}) {
  const response=await fetch(base+path,{method:body?"POST":"GET",headers:{"Content-Type":"application/json","x-test-user":user,"x-test-paid":"yes",...extra},body:body?JSON.stringify(body):undefined});
  const text=await response.text();
  return {status:response.status,text,data: (()=>{try{return JSON.parse(text)}catch{return {}}})()};
}
const credentials = {binanceApiKey:"valid-key-0123456789012345",binanceApiSecret:"secret-0123456789012345"};
try {
  assert.equal(connectionStatus({binance_status:"verified",coinalyze_status:"verified"}).connectionsComplete,false,
    "Legacy verification without stored keys must not enable navigation");
  const savedBoth = {binance_status:"verified",coinalyze_status:"verified",binance_ciphertext:"encrypted",coinalyze_ciphertext:"encrypted",capital_amount:null};
  assert.equal(connectionStatus(savedBoth).connectionsComplete,true,"Capital is not required to finish API setup");
  assert.equal(connectionStatus({...savedBoth,coinalyze_status:"failed"}).connectionsComplete,false);
  assert.equal((await request("/onboarding/binance",id(1),credentials,{"x-test-user":""})).status,401);
  assert.equal((await request("/onboarding/binance",id(1),credentials,{"x-test-paid":"no"})).status,403);
  assert.equal((await request("/settings/binance",id(1),credentials)).status,409);
  const initial=await request("/onboarding/binance",id(1),credentials);
  assert.equal(initial.status,200);
  assert.ok(!initial.text.includes(credentials.binanceApiSecret));
  const decrypt=value=>JSON.parse(crypto.privateDecrypt({key:privateKey,oaepHash:"sha256",padding:crypto.constants.RSA_PKCS1_OAEP_PADDING},Buffer.from(value,"base64")));
  assert.equal(decrypt(rows.get(id(1)).binance_ciphertext).apiSecret,credentials.binanceApiSecret);
  Object.assign(rows.get(id(1)),fresh());
  const oldCipher=rows.get(id(1)).binance_ciphertext;
  const invalid=await request("/settings/binance",id(1),{...credentials,binanceApiKey:"invalid-0123456789012345"});
  assert.equal(invalid.status,400);
  assert.equal(rows.get(id(1)).binance_ciphertext,oldCipher);
  assert.equal(rows.get(id(1)).binance_status,"verified");
  for (const changes of [{open_count:1},{desired_state:"running"},{actual_state:"error"},{heartbeat_at:new Date(0)},{snapshot_version:0}]) {
    Object.assign(rows.get(id(1)),fresh(),changes);
    const calls=verifications;
    assert.equal((await request("/settings/binance",id(1),credentials)).status,409);
    assert.equal(verifications,calls);
    assert.equal(rows.get(id(1)).binance_ciphertext,oldCipher);
  }
  Object.assign(rows.get(id(1)),fresh());
  race=true;
  assert.equal((await request("/settings/binance",id(1),credentials)).status,409);
  race=false;
  assert.equal(rows.get(id(1)).binance_ciphertext,oldCipher);
  Object.assign(rows.get(id(1)),fresh());
  assert.equal((await request("/settings/binance",id(1),credentials)).status,200);
  assert.equal(rows.get(id(1)).credential_version,2);
  const status=await request("/settings/connections",id(1));
  assert.equal(status.data.connections.canReplace,false);
  assert.ok(!status.text.includes(oldCipher));
  for(let offset=100;offset<600;offset+=25) {
    await Promise.all(Array.from({length:25},async(_,j)=>{
      const n=offset+j;
      const secret=`customer-${n}-secret-0123456789`;
      const response=await request("/onboarding/binance",id(n),{...credentials,binanceApiSecret:secret});
      assert.equal(response.status,200);
      assert.equal(decrypt(rows.get(id(n)).binance_ciphertext).apiSecret,secret);
      assert.ok(!response.text.includes(secret));
      const own=await request("/settings/connections",id(n));
      assert.equal(own.data.connections.binanceConnected,true);
      assert.ok(!own.text.includes(secret));
    }));
  }
  assert.throws(()=>checkReplacement({...fresh(),binance_ciphertext:"cipher",heartbeat_at:new Date(Date.now()+60000)},"binance"));
  console.log("PASS: auth/payment gates, initial setup, encrypted storage, safe replacement, failure preservation, race recheck, version acknowledgement; 500 isolated customers / 1,000 HTTP operations in 25-request batches. Mock database/provider, no exchange calls.");
} finally { server.closeAllConnections(); await new Promise(resolve=>server.close(resolve)); }
