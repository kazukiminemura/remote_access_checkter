import http from 'node:http';
import { readFile, writeFile, mkdir, rename } from 'node:fs/promises';
import { execFile } from 'node:child_process';
import { promisify } from 'node:util';
import { fileURLToPath } from 'node:url';
import { join, dirname } from 'node:path';
import { isIP } from 'node:net';
import { externalIP, normalizeSecurity, parseFirewall, summary } from './lib.mjs';

const root=dirname(fileURLToPath(import.meta.url)), run=promisify(execFile), data=join(root,'data');
await mkdir(data,{recursive:true});
async function readJSON(name,fallback) { try{return JSON.parse(await readFile(join(data,name),'utf8'));}catch(e){if(e.code==='ENOENT')return fallback;throw e;} }
async function save(name,value) {const path=join(data,name);await writeFile(path+'.tmp',JSON.stringify(value));await rename(path+'.tmp',path);}
let config=await readJSON('config.json',{targetIP:'',geoEnabled:false});
let events=await readJSON('events.json',[]), geo=await readJSON('geo.json',{});
let status=[], collecting=false, lastCollected=null, collectionError='', hostname='', truncated=false;
async function collect() {
  if(collecting)return;
  collecting=true;
  try {
    const script = `[Console]::OutputEncoding = [Text.UTF8Encoding]::new(); & '${join(root,'collector.ps1').replaceAll("'","''")}'`;
    const {stdout}=await run('powershell.exe',['-NoProfile','-NonInteractive','-ExecutionPolicy','Bypass','-EncodedCommand',Buffer.from(script,'utf16le').toString('base64')],{timeout:60000,maxBuffer:64*1024*1024,windowsHide:true,encoding:'utf8'});
    const raw=JSON.parse(stdout.replace(/^\uFEFF/,''));
    const current=[...normalizeSecurity(raw.events||[]),...(raw.firewall||[]).flatMap(f=>parseFirewall(f.text,f.path,raw.localIPs))];
    const cutoff=Date.now()-7*86400000;
    const merged=[...new Map([...events,...current].filter(e=>Date.parse(e.time)>cutoff).map(e=>[e.id,e])).values()].sort((a,b)=>Date.parse(b.time)-Date.parse(a.time));
    truncated=merged.length>50000 || (raw.firewall||[]).some(f=>f.limited) || (raw.status||[]).some(s=>s.limited);
    events=merged.slice(0,50000);status=raw.status||[];hostname=raw.hostname;lastCollected=new Date().toISOString();collectionError='';
    await save('events.json',events);
  } catch(e) {collectionError=e.code==='ENOENT'?'Windows PowerShellが見つかりません':e.message;}
  finally {collecting=false;}
}
let enriching=false;
async function enrich() {
  if(enriching || !config.geoEnabled)return;
  enriching=true;
  try {
    const ips=[...new Set(events.map(e=>e.ip))].filter(ip=>externalIP(ip)&&(!geo[ip] || geo[ip].retryAt<Date.now())).slice(0,5);
    for(const ip of ips) {
      if(!config.geoEnabled)break;
      const day=new Date().toISOString().slice(0,10);
      if(geo.__quota?.day!==day)geo.__quota={day,used:0};
      if(geo.__quota.used>=900)break;
      geo.__quota.used++;
      try {
        const response=await fetch(`https://ipwho.is/${encodeURIComponent(ip)}`,{signal:AbortSignal.timeout(5000)});
        if(!response.ok)throw Error('GeoIP lookup failed');
        const g=await response.json();
        if(!g.success || !Number.isFinite(g.latitude)||!Number.isFinite(g.longitude) || Math.abs(g.latitude)>90 || Math.abs(g.longitude)>180)throw Error('No coordinates');
        geo[ip]={country:g.country,countryCode:g.country_code,city:g.city,lat:g.latitude,lon:g.longitude};
      } catch {geo[ip]={retryAt:Date.now()+3600000};}
    }
    await save('geo.json',geo);
  } finally {enriching=false;}
}

function json(res,code,value) {res.writeHead(code,{'Content-Type':'application/json; charset=utf-8','Cache-Control':'no-store'});res.end(JSON.stringify(value));}
async function body(req) {let text='';for await(const chunk of req){text+=chunk;if(text.length>4096)throw Error('Request too large');}return JSON.parse(text);}
const server=http.createServer(async(req,res)=>{
  try {
    // Loopback binding plus same-origin checks prevent a remote site changing collector settings.
    if(!['127.0.0.1:4317','localhost:4317'].includes(req.headers.host))return json(res,403,{error:'Invalid host'});
    if(req.method==='POST' && req.headers.origin!==`http://${req.headers.host}`)return json(res,403,{error:'Invalid origin'});
    const url=new URL(req.url,'http://localhost:4317');
    if(req.method==='GET' && url.pathname==='/api/dashboard') {
      const hours=[1,24,168].includes(Number(url.searchParams.get('hours')))?Number(url.searchParams.get('hours')):24;
      const rows=events.filter(e=>Date.parse(e.time)>=Date.now()-hours*3600000);
      const geoStatus=config.geoEnabled?[{name:'geo',ok:geo.__quota?.used<900||!geo.__quota,message:geo.__quota?.used>=900?'GeoIPのアプリ内日次上限に到達。未取得のIPは翌UTC日に再試行します':'GeoIP有効。送信元の公開IPをipwho.isに送信し、推定位置を取得します'}]:[];
      return json(res,200,{events:rows.map(e=>({...e,geo:geo[e.ip]?.country?geo[e.ip]:null})),counts:summary(rows),config,status:[...status,...geoStatus],lastCollected,collecting,collectionError,hostname,truncated});
    }
    if(req.method==='POST' && url.pathname==='/api/settings') {
      const b=await body(req);
      if(typeof b.targetIP!=='string' || b.targetIP && !isIP(b.targetIP) || typeof b.geoEnabled!=='boolean')return json(res,400,{error:'有効なIPとGeoIP設定を指定してください'});
      config={targetIP:b.targetIP,geoEnabled:b.geoEnabled};await save('config.json',config);void enrich();return json(res,200,config);
    }
    if(req.method==='POST' && url.pathname==='/api/refresh') {void collect();return json(res,202,{collecting:true});}
    if(req.method==='GET' && url.pathname==='/api/export') {res.setHeader('Content-Disposition','attachment; filename="sentinel-events.json"');return json(res,200,{exportedAt:new Date().toISOString(),events});}
    const files={'/':'index.html','/app.js':'app.js','/styles.css':'styles.css','/world.geo.json':'world.geo.json'};
    if(req.method!=='GET'||!files[url.pathname])return json(res,404,{error:'Not found'});
    const ext=files[url.pathname].split('.').pop();res.writeHead(200,{'Content-Type':({html:'text/html',css:'text/css',js:'text/javascript',json:'application/json'})[ext]+'; charset=utf-8','Content-Security-Policy':"default-src 'self'; script-src 'self'; style-src 'self'; connect-src 'self'; img-src 'self' data:; frame-ancestors 'none'; base-uri 'none'; form-action 'self'",'X-Content-Type-Options':'nosniff','Referrer-Policy':'no-referrer'});res.end(await readFile(join(root,'public',files[url.pathname])));
  }catch(e){json(res,500,{error:e.message});}
});
server.listen(4317,'127.0.0.1',async()=>{
  await save('server.json',{pid:process.pid,startedMs:Math.round(Date.now()-process.uptime()*1000),script:join(root,'server.mjs')});
  console.log('SENTINEL → http://127.0.0.1:4317');
});
void collect();setInterval(()=>{void collect();void enrich();},30000);
