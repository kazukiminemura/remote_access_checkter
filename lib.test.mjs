import test from 'node:test';
import assert from 'node:assert/strict';
import { externalIP,normalizeSecurity,parseFirewall,summary } from './lib.mjs';
test('external IP excludes LAN, loopback, CGNAT and mapped LAN',()=>{
 for(const ip of ['127.0.0.1','10.0.0.2','192.168.1.3','172.31.1.1','100.64.0.1','::1','fe80::1','::ffff:192.168.1.1','-'])assert.equal(externalIP(ip),false,ip);
 assert.equal(externalIP('8.8.8.8'),true);assert.equal(externalIP('2606:4700:4700::1111'),true);
});
test('firewall counts incoming public packets only',()=>{
 const rows=parseFirewall('#Fields: date time action protocol src-ip dst-ip src-port dst-port path\n2026-10-14 09:00:00 DROP TCP 8.8.8.8 192.168.1.3 40000 3389 RECEIVE\n2026-10-14 09:00:01 ALLOW TCP 8.8.4.4 192.168.1.3 443 40000 SEND\n2026-10-14 09:00:02 ALLOW TCP 10.0.0.1 192.168.1.3 443 40000 RECEIVE');
 assert.equal(rows.length,1);assert.equal(summary(rows).blocked,1);assert.equal(summary(rows).success,0);
});
test('session correlation requires success, correct context and open session',()=>{
 const e=(eventId,recordId,data)=>({eventId,recordId,time:new Date(1760000000000+recordId*1000).toISOString(),data});
 const rows=normalizeSecurity([e(4688,1,{SubjectLogonId:'0xabc',NewProcessName:'before.exe'}),e(4624,2,{LogonType:'10',IpAddress:'8.8.8.8',TargetLogonId:'0xabc',TargetUserName:'alice'}),e(4688,3,{SubjectLogonId:'0xABC',TargetLogonId:'0x0',NewProcessName:'cmd.exe'}),e(4688,4,{SubjectLogonId:'0xabc',TargetLogonId:'0xother',NewProcessName:'other.exe'}),e(4634,5,{TargetLogonId:'0xabc'}),e(4688,6,{SubjectLogonId:'0xabc',NewProcessName:'after.exe'}),e(4625,7,{LogonType:'3',IpAddress:'8.8.4.4',TargetUserName:'bob'}),e(4624,8,{LogonType:'2',IpAddress:'8.8.4.4',TargetLogonId:'0xlocal'})]);
 assert.deepEqual(rows.map(e=>e.kind),['success','process','failed']);assert.equal(rows[1].detail,'cmd.exe');assert.equal(rows[1].ip,'8.8.8.8');
 assert.equal(rows[1].sessionKey,rows[0].sessionKey);
});
test('reboot clears session context and reused record IDs remain distinct',()=>{
 const rows=normalizeSecurity([{eventId:4624,recordId:1,time:'2026-10-14T00:00:00Z',data:{LogonType:'10',IpAddress:'8.8.8.8',TargetLogonId:'0x1'}},{eventId:4608,recordId:2,time:'2026-10-14T00:01:00Z',data:{}},{eventId:4688,recordId:3,time:'2026-10-14T00:02:00Z',data:{SubjectLogonId:'0x1',NewProcessName:'unrelated.exe'}},{eventId:4624,recordId:1,time:'2026-10-14T00:03:00Z',data:{LogonType:'10',IpAddress:'8.8.8.8',TargetLogonId:'0x1'}}]);
 assert.equal(rows.length,2);assert.notEqual(rows[0].id,rows[1].id);
});
