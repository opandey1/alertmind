// Injected into the hash-bound client by build_candidate.py. No runtime options.
function alertmindBrokerPolicy() {
  const fs = require('fs');
  const crypto = require('crypto');
  const path = '/etc/wazuh-dashboard/certs/alertmind-server-api.pem';
  const pin = '5037899c0818f8332b09fc144bd7bd72a3b2ca033f46dad56c67c284d611ce87';
  const fail = () => { throw new Error('ALERTMIND_BROKER_POLICY'); };
  let pem;
  // Root ownership and no non-root writers prevent service-owned path swaps.
  // Root compromise and an already compromised Node process are not contained.
  const paths = ['/', '/etc', '/etc/wazuh-dashboard', '/etc/wazuh-dashboard/certs', path];
  const before = [];
  let fd;
  try {
    if (typeof fs.constants.O_NOFOLLOW !== 'number') fail();
    for (let i = 0; i < paths.length; i++) {
      const s = fs.lstatSync(paths[i]);
      if (s.isSymbolicLink() || s.uid !== 0 || (s.mode & 0o022) ||
          (i < paths.length - 1 ? !s.isDirectory() : !s.isFile())) fail();
      before.push(s);
    }
    const last = before[before.length - 1];
    if (last.size < 1 || last.size > 65536) fail();
    fd = fs.openSync(path, fs.constants.O_RDONLY | fs.constants.O_NOFOLLOW);
    const opened = fs.fstatSync(fd);
    if (!opened.isFile() || opened.dev !== last.dev || opened.ino !== last.ino ||
        opened.size !== last.size || opened.uid !== 0 || (opened.mode & 0o022)) fail();
    const buf = Buffer.alloc(65537);
    const n = fs.readSync(fd, buf, 0, buf.length, 0);
    if (n !== last.size) fail();
    pem = buf.subarray(0, n).toString('ascii');
    for (let i = 0; i < paths.length; i++) {
      const a = before[i], b = fs.lstatSync(paths[i]);
      if (a.dev !== b.dev || a.ino !== b.ino || a.mode !== b.mode ||
          a.uid !== b.uid || a.size !== b.size || a.mtimeMs !== b.mtimeMs ||
          a.ctimeMs !== b.ctimeMs) fail();
    }
    if (!/^-----BEGIN CERTIFICATE-----\r?\n[A-Za-z0-9+/=\r\n]+\r?\n-----END CERTIFICATE-----\r?\n?$/.test(pem)) fail();
    const cert = new crypto.X509Certificate(pem);
    if (crypto.createHash('sha256').update(cert.raw).digest('hex') !== pin ||
        !(Date.parse(cert.validFrom) <= Date.now() && Date.now() < Date.parse(cert.validTo)) ||
        cert.checkHost('localhost', { subject: 'never' }) !== 'localhost') fail();
  } catch (_) {
    fail();
  } finally {
    if (fd !== undefined) fs.closeSync(fd);
  }
  const lookup = (hostname, options, callback) => {
    if (typeof options === 'function') { callback = options; options = {}; }
    if (hostname !== 'localhost') return callback(new Error('ALERTMIND_BROKER_DNS'));
    if (options && options.all) return callback(null, [{ address: '127.0.0.1', family: 4 }]);
    callback(null, '127.0.0.1', 4);
  };
  const agent = new _https.default.Agent({ rejectUnauthorized: true, ca: pem, lookup });
  const guard = config => {
    try {
      if (typeof config.url !== 'string' ||
          !/^https:\/\/localhost:55000\/(?!\/)/.test(config.url) ||
          /[\x00-\x20\x7f\\#]/.test(config.url)) fail();
      const url = new URL(config.url);
      if (url.origin !== 'https://localhost:55000' || url.username || url.password || url.hash) fail();
      // Axios has flattened common/method headers. Host also affects Node SNI.
      for (const key of Object.keys(config.headers || {})) {
        if (/^(host|proxy-authorization|proxy-connection)$/i.test(key)) fail();
      }
      // Lock transport at the last axios request boundary, including auth/retries.
      config.httpsAgent = agent;
      config.proxy = false;
      config.maxRedirects = 0;
      config.timeout = 30000;
      return config;
    } catch (_) { fail(); }
  };
  return { agent, guard };
}
