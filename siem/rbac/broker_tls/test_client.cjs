'use strict';
// Actual vendor client + package axios + native Node TLS. Only dependencies on
// host/context/cookie and Linux certificate metadata are synthetic adapters.
const fs = require('fs'), path = require('path'), vm = require('vm');
const https = require('https'), http = require('http'), crypto = require('crypto');
const assert = require('assert/strict');
// The original has no fixed resolver. Keep its control on our IPv4-only fixture.
require('dns').setDefaultResultOrder('ipv4first');
const { createRequire } = require('module');
const [stage, fixturePath] = process.argv.slice(2);
const fixture = JSON.parse(fs.readFileSync(fixturePath, 'utf8'));
const manifest = JSON.parse(fs.readFileSync(path.join(stage, 'manifest.json'), 'utf8'));
const sha = b => crypto.createHash('sha256').update(b).digest('hex');
const canonical = x => Array.isArray(x) ? x.map(canonical) : x && typeof x === 'object' ? Object.fromEntries(Object.keys(x).sort().map(k=>[k,canonical(x[k])])) : x;
const contract = JSON.parse(fs.readFileSync(path.join(__dirname,'contract.json'),'utf8'));
for (const [key,value] of Object.entries(contract)) assert.equal(manifest[key],value);
assert.equal(sha(JSON.stringify(canonical(manifest.files))),contract.files_digest);
// A new, unlisted nested dependency can shadow a correctly hashed root copy.
// Reject additions and symlinks before loading ANY staged JavaScript.
const observed = [];
function inventory(directory, relative='') {
  assert(!fs.lstatSync(directory).isSymbolicLink());
  for (const name of fs.readdirSync(directory)) {
    const full=path.join(directory,name), rel=relative ? relative+'/'+name : name;
    const stat=fs.lstatSync(full); assert(!stat.isSymbolicLink());
    if (stat.isDirectory()) inventory(full,rel);
    else { assert(stat.isFile()); observed.push(rel); }
  }
}
inventory(stage);
assert.equal(observed.sort().join('\n') === [...Object.keys(manifest.files),'manifest.json'].sort().join('\n'),true,'STAGED_FILE_SET');
for (const [name, expected] of Object.entries(manifest.files)) {
  assert(!name.includes('..') && !path.isAbsolute(name));
  const b = fs.readFileSync(path.join(stage, name));
  assert.equal(b.length, expected.bytes); assert.equal(sha(b), expected.sha256);
}
const realRequire = createRequire(path.join(stage, 'original.cjs'));
assert.equal(realRequire('axios/package.json').version, '1.12.2');
const source = fs.readFileSync(path.join(stage, 'candidate.cjs'), 'utf8');
const original = fs.readFileSync(path.join(stage, 'original.cjs'), 'utf8');
const productionPin = '5037899c0818f8332b09fc144bd7bd72a3b2ca033f46dad56c67c284d611ce87';
assert.equal(source.split(productionPin).length, 2);
const bindings = [];
let count = 0;
function pass(label) { count++; console.log('PASS ' + label); }
// Remove ambient proxies for original control, then explicitly test hostile ones.
const proxyNames = ['http_proxy','https_proxy','all_proxy','no_proxy',
  'npm_config_http_proxy','npm_config_https_proxy','npm_config_proxy',
  'npm_config_no_proxy','npm_config_noproxy'];
function clearProxies() {
  for (const name of proxyNames) {
    delete process.env[name]; delete process.env[name.toUpperCase()];
  }
}
clearProxies();
assert.notEqual(process.env.NODE_TLS_REJECT_UNAUTHORIZED, '0');

function certFs(mode='good') {
  const pem = Buffer.from(mode === 'malformed' ? 'bad' : mode === 'expired' ? fixture.expiredAnchor.cert :
    mode === 'wrongHostAnchor' ? fixture.wrongHostAnchor.cert : fixture.anchor.cert);
  let calls = 0;
  function stat(file) {
    calls++;
    if (mode === 'missing') throw new Error('ENOENT');
    const isFile = file.endsWith('.pem');
    return { uid: mode === 'owner' ? 123 : 0, dev: 1, ino: isFile ? 10 : file.length,
      mode: mode === 'writable' ? 0o777 : isFile ? 0o644 : 0o755,
      size: isFile ? pem.length : 1, mtimeMs: mode === 'changed' && calls > 5 ? 2 : 1, ctimeMs: 1,
      isFile:()=>isFile, isDirectory:()=>!isFile, isSymbolicLink:()=>mode === 'symlink' };
  }
  return { constants:{ O_NOFOLLOW: 131072, O_RDONLY:0 }, lstatSync:stat,
    openSync:()=>17, fstatSync:()=>stat('/fixture.pem'), closeSync:()=>{},
    readSync:(_fd, b)=>{ pem.copy(b); return pem.length; } };
}

function client(text=source, {trust='good', pin=fixture.pin}={}) {
  const exports = {};
  const bound = text.replace(productionPin, pin);
  const customRequire = n => n === 'fs' ? certFs(trust) : n === './cookie' ?
    {getCookieValueByName:()=> 'fixture-cookie-token'} : realRequire(n);
  vm.runInThisContext('(function(require,exports){\n'+bound+'\n})', {filename:'fixture-client.cjs'})(customRequire,exports);
  const state = {url:'https://localhost', port:55000, runAs:true};
  const c = new exports.ServerAPIClient({}, {
    get:async()=>({url:state.url,port:state.port,username:'fixture-user',password:'fixture-password'}),
    isEnabledAuthWithRunAs:()=>state.runAs
  }, { getCurrentUser:async()=>({authContext:{user_name:'fixture-analyst'}}) });
  bindings.push(c);
  return {c,state};
}

let arrivals = [], authCount = 0, failOnce = false, forcedStatus = 0, redirect = 0;
const apiHandler = (req,res) => {
  let body=''; req.on('data',b=>body+=b); req.on('end',()=>{
    arrivals.push({url:req.url,auth:req.headers.authorization,host:req.headers.host,body,method:req.method,ctype:req.headers['content-type']});
    res.setHeader('content-type','application/json');
    if (redirect) { res.writeHead(redirect, {location:'https://localhost:55001/capture'}); res.end('{}'); return; }
    if (forcedStatus) { res.writeHead(forcedStatus); res.end(JSON.stringify({error:'synthetic-http-error'})); return; }
    if (req.url.startsWith('/security/user/authenticate')) { authCount++; res.end(JSON.stringify({data:{token:'fixture-token-'+authCount}})); return; }
    if (failOnce) { failOnce=false; res.writeHead(401); res.end('{}'); return; }
    res.end(JSON.stringify({ok:true}));
  });
};
async function server(kind, port=55000, handler=apiHandler) {
  const s = https.createServer(fixture[kind], handler);
  await new Promise((resolve,reject)=>{s.once('error',reject);s.listen(port,'127.0.0.1',resolve);});
  return s;
}
async function close(s) { s.closeAllConnections(); await new Promise(r=>s.close(r)); }
async function denied(fn) {
  let caught;
  try { await fn(); } catch(e) { caught=e; }
  assert(caught, 'expected rejection');
  const serialized=JSON.stringify(caught);
  for(const secret of ['fixture-password','fixture-cookie-token','fixture-token-','Basic ']) assert(!serialized.includes(secret));
  assert(!caught.config && !caught.request && !caught.cause);
  return caught;
}
const auth = c => c._authenticate('one',{useRunAs:false});
const read = c => c._request('GET','/agents',{}, {apiHostID:'one',token:'fixture-token-read'});

function mutateOnce(text, anchor, replacement) {
  assert.equal(text.split(anchor).length,2,'mutation requires exactly one anchor');
  const changed=text.replace(anchor,replacement);
  assert.notEqual(changed,text,'mutation must change bytes');
  return changed;
}
function assertAnchorRejected(text) {
  // Correct fingerprint + valid dates/metadata isolate the SAN-only branch.
  const pin=sha(new crypto.X509Certificate(fixture.wrongHostAnchor.cert).raw);
  assert.throws(()=>client(text,{trust:'wrongHostAnchor',pin}),/ALERTMIND_BROKER_POLICY/);
}
async function assertLookup(c) {
  const lookup=c._axios.defaults.httpsAgent.options.lookup;
  assert.equal(typeof lookup,'function','fixed resolver must be installed');
  for (const host of ['localhost','wrong.invalid','127.0.0.1','LOCALHOST']) {
    for (const shape of ['plain','all','callback-only']) {
      let timer, calls=0;
      try {
        const result=await Promise.race([
          new Promise(resolve=>{
            const callback=(...args)=>{calls++;resolve(args);};
            if(shape==='callback-only') lookup(host,callback);
            else lookup(host,shape==='all'?{all:true}:{},callback);
          }),
          new Promise((_,reject)=>{timer=setTimeout(()=>reject(new Error('LOOKUP_TIMEOUT')),1000);})
        ]);
        await new Promise(resolve=>setImmediate(resolve));
        assert.equal(calls,1);
        if(host!=='localhost') {
          assert(result[0] instanceof Error); assert.equal(result[0].message,'ALERTMIND_BROKER_DNS');
          assert.equal(result.length,1);
        } else if(shape==='all') assert.deepEqual(result,[null,[{address:'127.0.0.1',family:4}]]);
        else assert.deepEqual(result,[null,'127.0.0.1',4]);
      } finally {clearTimeout(timer);}
    }
  }
}

async function main() {
  for(const mode of ['missing','malformed','owner','writable','symlink','changed','expired']) {
    const pin=mode==='expired' ? sha(new crypto.X509Certificate(fixture.expiredAnchor.cert).raw) : fixture.pin;
    assert.throws(()=>client(source,{trust:mode,pin}),/ALERTMIND_BROKER_POLICY/);
  }
  assert.throws(()=>client(source,{pin:'0'.repeat(64)}),/ALERTMIND_BROKER_POLICY/);
  pass('trust failure matrix (synthetic Linux metadata; no production trust loaded)');
  assertAnchorRejected(source);
  const hostMut=mutateOnce(source,"cert.checkHost('localhost', { subject: 'never' }) !== 'localhost'",'false');
  assert.throws(()=>assertAnchorRejected(hostMut),assert.AssertionError);
  pass('wrong-SAN pinned anchor rejected at construction; removing checkHost detected');
  await assertLookup(client().c);
  const lookupMut=mutateOnce(source,'rejectUnauthorized: true, ca: pem, lookup','rejectUnauthorized: true, ca: pem');
  await assert.rejects(()=>assertLookup(client(lookupMut).c),assert.AssertionError);
  pass('fixed resolver callback formats and non-localhost rejection; removing lookup detected');

  // Original demonstrates the defect on the very same wrong-host TLS fixture.
  let s=await server('wronghost'); arrivals=[];
  const old=client(original).c; await auth(old); assert.equal(arrivals.length,1);
  assert.equal(arrivals[0].auth,'Basic '+Buffer.from('fixture-user:fixture-password').toString('base64'));
  await close(s); pass('original client transmits synthetic Basic credentials to wrong-host peer');
  for(const kind of ['wronghost','untrusted','expiredPeer']) {
    s=await server(kind); arrivals=[];
    const {c}=client();
    for(const fn of [()=>auth(c),()=>read(c),()=>c.asInternalUser.authenticate('one'),
      ()=>c.asInternalUser.request('GET','/agents',{}, {apiHostID:'one'}),
      ()=>c.asScoped({}, {headers:{cookie:'synthetic'}}).authenticate('one')]) await denied(fn);
    assert.equal(arrivals.length,0); await close(s); pass(kind+': zero HTTP credential arrivals across shared entry paths');
  }
  s=await server('good'); arrivals=[]; authCount=0;
  const {c,state}=client();
  const scoped=c.asScoped({}, {headers:{cookie:'synthetic'}});
  await scoped.authenticate('one'); assert.equal(arrivals.at(-1).url,'/security/user/authenticate/run_as');
  assert.deepEqual(JSON.parse(arrivals.at(-1).body),{user_name:'fixture-analyst'});
  state.runAs=false; await scoped.authenticate('one'); assert.equal(arrivals.at(-1).url,'/security/user/authenticate');
  assert.equal(arrivals.at(-1).auth,'Basic '+Buffer.from('fixture-user:fixture-password').toString('base64'));
  await scoped.request('POST','/agents',{body:'<xml/>',headers:{'Content-Type':'application/xml'},params:{q:'https://example.invalid'}},{apiHostID:'one',token:'ignored'});
  assert.equal(arrivals.at(-1).auth,'Bearer fixture-cookie-token'); assert.equal(arrivals.at(-1).body,'<xml/>');
  assert.equal(arrivals.at(-1).ctype,'application/xml'); assert(arrivals.at(-1).url.includes('q='));
  pass('scoped run_as/non-run_as, Basic/cookie precedence, XML and query semantics');
  const internal=c.asInternalUser;
  await internal.request('GET','/agents',{}, {apiHostID:'one'}); const n=authCount;
  await internal.request('GET','/agents',{}, {apiHostID:'one'}); assert.equal(authCount,n);
  await internal.request('GET','/agents',{}, {apiHostID:'one',forceRefresh:true}); assert.equal(authCount,n+1);
  failOnce=true; await internal.request('GET','/agents',{}, {apiHostID:'one'}); assert.equal(authCount,n+2);
  pass('internal cold/warm cache, forceRefresh and HTTP 401 refresh');
  for(const status of [401,403,404,500]) {
    forcedStatus=status; const e=await denied(()=>read(c)); assert.equal(e.response.status,status);
    assert.equal(e.response.data.error,'synthetic-http-error');
  }
  forcedStatus=0; pass('HTTP status/data preserved; credential-bearing axios objects removed');
  let before=arrivals.length;
  for(const url of ['http://localhost','https://127.0.0.1','https://LOCALHOST','https://user@localhost','https://localhost/extra','https://evil.invalid']) {
    state.url=url; await denied(()=>auth(c)); await denied(()=>read(c));
    await denied(()=>internal.request('GET','/agents',{}, {apiHostID:'one'}));
  }
  state.url='https://localhost'; state.port=55001; await denied(()=>read(c)); state.port=55000;
  for(const p of ['@evil.invalid/x','//evil.invalid/x','/x#fragment','/x\\bad','/x\n', '/x y']) await denied(()=>c._request('GET',p,{}, {apiHostID:'one',token:'fixture-token-read'}));
  for(const headers of [{Host:'evil.invalid'},{hOsT:'evil.invalid'},{common:{Host:'evil.invalid'}},{get:{Host:'evil.invalid'}},{'Proxy-Authorization':'fixture-password'}]) await denied(()=>c._request('GET','/agents',{headers},{apiHostID:'one',token:'fixture-token-read'}));
  assert.equal(arrivals.length,before); pass('raw/final origin, malformed path, flattened Host/proxy-header rejection');
  await c._request('POST','/agents',{maxRedirects:10,proxy:{host:'evil.invalid'},httpsAgent:'bad',adapter:'bad'}, {apiHostID:'one',token:'fixture-token-read'});
  assert.equal(JSON.parse(arrivals.at(-1).body).maxRedirects,10); pass('transport-shaped body fields cannot override axios configuration');

  let capture=0;
  const target=await server('good',55001,(_req,res)=>{capture++;res.end('{}');});
  for(const status of [301,302,303,307,308]) {
    redirect=status; await denied(()=>auth(c)); await denied(()=>read(c)); assert.equal(capture,0);
  }
  redirect=0; pass('all five redirect classes blocked; secondary-origin arrivals=0');
  let proxyHits=0;
  const proxy=http.createServer((_req,res)=>{proxyHits++;res.writeHead(502);res.end();});
  await new Promise((r,j)=>{proxy.once('error',j);proxy.listen(55002,'127.0.0.1',r);});
  const proxyUrl='http://127.0.0.1:55002';
  const getProxy=realRequire('./node_modules/axios/node_modules/proxy-from-env').getProxyForUrl;
  const proxyMut=client(mutateOnce(source,'config.proxy = false;', 'config.proxy = undefined;')).c;
  for(const lower of ['https_proxy','all_proxy','http_proxy','npm_config_https_proxy','npm_config_proxy','npm_config_http_proxy']) {
    for(const name of [lower,lower.toUpperCase()]) {
      clearProxies(); process.env[name]=proxyUrl;
      const beforeProxy=proxyHits;
      await auth(c); await read(c); assert.equal(proxyHits,beforeProxy);
      if(lower==='http_proxy' || lower==='npm_config_http_proxy') {
        // HTTPS-only client: HTTP variable does not select an HTTPS proxy.
        assert.equal(getProxy('http://localhost:55000/'),proxyUrl);
        assert.equal(getProxy('https://localhost:55000/'),'');
      } else {
        assert.equal(getProxy('https://localhost:55000/'),proxyUrl);
        try {await auth(proxyMut);} catch(_) {} assert(proxyHits>beforeProxy);
      }
    }
  }
  // Exclusions must not silently neutralize the proxy mutation on npm hosts.
  for(const name of ['npm_config_no_proxy','NPM_CONFIG_NO_PROXY','no_proxy','NO_PROXY']) {
    clearProxies(); process.env.npm_config_https_proxy=proxyUrl; process.env[name]='*';
    assert.equal(getProxy('https://localhost:55000/'),'');
  }
  clearProxies(); process.env.npm_config_https_proxy=proxyUrl; process.env.npm_config_noproxy='*';
  assert.equal(getProxy('https://localhost:55000/'),proxyUrl,'npm noproxy spelling is not read by this dependency');
  clearProxies(); await close(proxy);
  pass('standard/npm proxy families and casing ignored by candidate; HTTPS proxy mutations detected; exclusions isolated');

  // Existing redirect/origin/TLS mutations remain separate controls.
  const originMut=client(source.replace("if (typeof config.url !== 'string' ||", "if (false && (typeof config.url !== 'string' ||").replace('/[\\x00-\\x20\\x7f\\\\#]/.test(config.url)) fail();','/[\\x00-\\x20\\x7f\\\\#]/.test(config.url))) fail();').replace("if (url.origin !== 'https://localhost:55000' || url.username || url.password || url.hash) fail();",'')).c;
  originMut.manageHosts.get=async()=>({url:'https://localhost',port:55001,username:'fixture-user',password:'fixture-password'});
  try {await auth(originMut);} catch(_) {} assert(capture>0); capture=0;
  redirect=307;
  const redirMut=client(source.replace('config.maxRedirects = 0;', 'config.maxRedirects = 5;')).c;
  try {await auth(redirMut);} catch(_) {} assert(capture>0); redirect=0;
  await close(target); await close(s);
  s=await server('wronghost'); arrivals=[];
  const tlsMut=client(source.replace('rejectUnauthorized: true, ca: pem','rejectUnauthorized: false, ca: pem')).c;
  await auth(tlsMut); assert.equal(arrivals.length,1); await close(s);
  assert.equal(arrivals[0].auth,'Basic '+Buffer.from('fixture-user:fixture-password').toString('base64'));
  pass('mutation controls detected: TLS bypass, removed origin gate, redirects, proxy inheritance');
  const e=await denied(()=>auth(c)); assert.equal(e.code,'ECONNREFUSED'); pass('connection-refused compatibility retained');
  console.log(JSON.stringify({scope:'synthetic actual-client tests only',groups:count,node:process.version,
    platform:process.platform,openssl:process.versions.openssl,axios:'1.12.2',candidate_sha256:manifest.candidate_sha256,
    linux_filesystem_metadata:'adapted, not native proof',fixture_pin:'synthetic substitution in memory only',
    live_acceptance:false,packaged_linux_runtime_executed:false}));
}
main().catch(e=>{console.error('FAIL synthetic fixture:', e.name, e.message.startsWith('ALERTMIND')?e.message:'assertion or runtime failure', e.code || '', e.response?.status || '', String(e.stack).match(/test_client.cjs:\d+:\d+/)?.[0] || ''); process.exitCode=1;})
  .finally(()=>{for(const c of bindings) c._axios.defaults.httpsAgent.destroy(); setTimeout(()=>process.exit(process.exitCode||0),50);});
