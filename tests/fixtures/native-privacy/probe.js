'use strict';
const fs=require('node:fs');
const https=require('node:https');
const {probe}=require('/pilot/probe.js');
const value=JSON.parse(fs.readFileSync('/pilot/privacy.json'));
(async () => {
  const result=await probe(https,fs.readFileSync('/pilot/ca.crt'),'/pilot',200,JSON.stringify({result:value.response}),4000);
  process.stdout.write(JSON.stringify({ok:result.expected_body && result.exception==='none'})+'\n');
})().catch(()=>{process.stderr.write('privacy probe failed\n');process.exitCode=1;});
