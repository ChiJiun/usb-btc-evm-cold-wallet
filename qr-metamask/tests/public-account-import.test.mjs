import test from 'node:test';
import assert from 'node:assert/strict';
import { PublicAccountImport } from '../src/public_account_import.mjs';

function deferred() {
  let resolve, reject;
  const promise=new Promise((done,fail)=>{resolve=done;reject=fail;});
  return {promise,resolve,reject};
}
const file=(text)=>({size:50,text:()=>text});

test('later public account wins when the earlier file completes after it',async()=>{
  const importer=new PublicAccountImport(info=>({address:info.address}));
  const old=deferred(), current=deferred();
  const first=importer.read(file(old.promise));
  const latest=importer.read(file(current.promise));
  current.resolve('{"address":"0xB"}');
  assert.deepEqual(await latest,{info:{address:'0xB'},validated:{address:'0xB'}});
  old.resolve('invalid json');
  assert.equal(await first,null);
});
test('stale file I/O errors cannot override the current account',async()=>{
  const importer=new PublicAccountImport(info=>info);
  const slow=deferred();
  const pending=importer.read(file(slow.promise));
  assert.deepEqual(await importer.read(file(Promise.resolve('{"ready":true}'))),
    {info:{ready:true},validated:{ready:true}});
  slow.reject(new Error('obsolete file read failure'));
  assert.equal(await pending,null);
});
test('cancel or pagehide invalidates pending public file reads',async()=>{
  const importer=new PublicAccountImport(info=>info);
  const slow=deferred();
  const pending=importer.read(file(slow.promise));
  importer.cancel();
  slow.resolve('{"address":"old"}');
  assert.equal(await pending,null);
});
test('malformed current selection fails closed',async()=>{
  const importer=new PublicAccountImport(info=>info);
  await assert.rejects(()=>importer.read(null),/大小有限/);
  await assert.rejects(()=>importer.read(file(Promise.resolve('invalid'))),SyntaxError);
});
