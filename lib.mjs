import { isIP } from 'node:net';

export function externalIP(ip) {
  if (!isIP(ip)) return false;
  if (ip.toLowerCase().startsWith('::ffff:')) return externalIP(ip.slice(7));
  if (isIP(ip) === 6) return !/^(::|fc|fd|fe[89ab]|ff|2001:db8)/i.test(ip);
  const [a,b] = ip.split('.').map(Number);
  return !(a === 0 || a === 10 || a === 127 || a >= 224 || a === 169 && b === 254 || a === 172 && b >= 16 && b <= 31 || a === 192 && b === 168 || a === 100 && b >= 64 && b <= 127 || a === 198 && [18,19].includes(b));
}

export function normalizeSecurity(events) {
  const result = [], sessions = new Map();
  for (const event of [...events].sort((a,b) => Date.parse(a.time)-Date.parse(b.time))) {
    const d = event.data || {}, id = Number(event.eventId);
    const eventKey=`security:${event.time}:${event.recordId}`;
    if (id===4608) sessions.clear();
    if ([4624,4625].includes(id) && ['3','10'].includes(String(d.LogonType)) && externalIP(d.IpAddress)) {
      const row = {id:eventKey,time:event.time,kind:id===4624?'success':'failed',ip:d.IpAddress,port:d.IpPort||'',user:d.TargetUserName||'',session:d.TargetLogonId||'',sessionKey:id===4624?eventKey:'',detail:id===4624?`リモート認証成功 · Logon Type ${d.LogonType}`:`認証失敗 · ${d.Status||''}`,source:'Security',eventId:id};
      result.push(row);
      if (id===4624 && row.session) sessions.set(row.session.toLowerCase(),row);
    }
    if (id===4634) sessions.delete((d.TargetLogonId||'').toLowerCase());
    if (id===4688) {
      // The target context is authoritative when present; don't assign another user's process to its creator.
      const logon = d.TargetLogonId && d.TargetLogonId !== '0x0' ? d.TargetLogonId : d.SubjectLogonId;
      const session = sessions.get((logon||'').toLowerCase());
      if (session) result.push({id:eventKey,time:event.time,kind:'process',ip:session.ip,port:'',user:d.TargetUserName||d.SubjectUserName||session.user,session:session.session,sessionKey:session.sessionKey,detail:d.CommandLine||d.NewProcessName||'プロセス作成（詳細なし）',source:'Security',eventId:id,parent:d.ParentProcessName||'',commandRecorded:!!d.CommandLine});
    }
  }
  return result;
}

export function parseFirewall(text, source='Firewall', localIPs=[]) {
  let fields = []; const result=[];
  for (const line of text.split(/\r?\n/)) {
    if (line.startsWith('#Fields:')) { fields=line.slice(8).trim().split(/\s+/); continue; }
    if (!line || line.startsWith('#') || !fields.length) continue;
    const values=line.trim().split(/\s+/), row=Object.fromEntries(fields.map((f,i)=>[f,values[i]]));
    const incoming = row.path === 'RECEIVE' || (!row.path && localIPs.includes(row['dst-ip']));
    if (!incoming || !externalIP(row['src-ip']) || !['ALLOW','DROP'].includes(row.action)) continue;
    const time=new Date(`${row.date}T${row.time}`);
    if (!Number.isFinite(+time)) continue;
    // One record is one logged packet, not a unique connection or intrusion attempt.
    result.push({id:`fw:${source}:${line}`,time:time.toISOString(),kind:row.action==='DROP'?'blocked':'allowed',ip:row['src-ip'],destination:row['dst-ip'],port:row['dst-port'],protocol:row.protocol,detail:`${row.protocol} → ${row['dst-port']} · ${row.action}`,source:'Firewall'});
  }
  return result;
}

export function summary(events) {
  const counts={packets:0,blocked:0,allowed:0,failed:0,success:0,process:0};
  for (const e of events) { if(e.kind in counts) counts[e.kind]++; if(['blocked','allowed'].includes(e.kind)) counts.packets++; }
  return {...counts,uniqueIPs:new Set(events.map(e=>e.ip)).size};
}
