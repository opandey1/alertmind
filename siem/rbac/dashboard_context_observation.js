/* Review-gated Firefox console observation. Two fixed GETs, no session export.
 * Run only in the approved, fresh socanalyst lab-profile session. Never paste
 * credentials, tokens, HARs or raw responses into this script or an agent chat.
 */
(async () => {
  'use strict';
  const endpoint = '/api/v1/configuration/account';
  const role = 'alertmind_socanalyst_ro';
  const fields = ['user_name', 'is_reserved', 'is_hidden', 'is_internal_user',
    'user_requested_tenant', 'backend_roles', 'custom_attribute_names', 'tenants', 'roles'];
  const codes = new Set(['ORIGIN', 'CHALLENGE', 'HTTP', 'RESPONSE', 'SIZE', 'SHAPE',
    'IDENTITY', 'GRANTS', 'DRIFT', 'TIMEOUT']);
  const need = (ok, code) => { if (!ok) throw new Error(code); };
  const object = x => x !== null && typeof x === 'object' && !Array.isArray(x);
  const canonical = x => JSON.stringify(object(x) ? Object.fromEntries(
    Object.keys(x).sort().map(k => [k, JSON.parse(canonical(x[k]))])) :
    Array.isArray(x) ? x.map(v => JSON.parse(canonical(v))) : x);
  // Scoped subset of v4.14.7 FIND: one literal string key/value. MATCH also
  // accepts a literal inside a list; FIND visits dictionaries inside lists.
  // Never use this to interpret regexes, logical operators or unknown rules.
  function findLiteral(context, key, literal) {
    if (Object.hasOwn(context, key)) {
      const value = context[key];
      if (value === literal || (Array.isArray(value) && value.includes(literal))) return true;
    }
    for (const value of Object.values(context)) {
      if (object(value) && findLiteral(value, key, literal)) return true;
      if (Array.isArray(value) && value.some(v => object(v) && findLiteral(v, key, literal))) return true;
    }
    return false;
  }
  function validate(value) {
    need(object(value) && Object.keys(value).sort().join('|') === fields.slice().sort().join('|'), 'SHAPE');
    need(value.user_name === 'socanalyst' && value.is_internal_user === true &&
      value.is_reserved === false && value.is_hidden === false, 'IDENTITY');
    need(Array.isArray(value.backend_roles) && value.backend_roles.length === 0 &&
      Array.isArray(value.custom_attribute_names) && value.custom_attribute_names.length === 0 &&
      Array.isArray(value.roles) && value.roles.length === 1 && value.roles[0] === role, 'GRANTS');
    need(value.user_requested_tenant === null || (typeof value.user_requested_tenant === 'string' &&
      value.user_requested_tenant.length <= 128), 'SHAPE');
    need(object(value.tenants) && Object.keys(value.tenants).length <= 32 &&
      Object.entries(value.tenants).every(([k, v]) => k.length <= 128 && typeof v === 'boolean'), 'SHAPE');
    return value;
  }
  async function read() {
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), 10000);
    let reader;
    try {
      const response = await fetch(endpoint, {method: 'GET', credentials: 'same-origin',
        cache: 'no-store', redirect: 'error', signal: controller.signal});
      need(response.status === 200, 'HTTP'); // Do not read failure bodies.
      need(response.url === location.origin + endpoint && response.type === 'basic' &&
        response.headers.get('Content-Type')?.split(';')[0].trim() === 'application/json', 'RESPONSE');
      reader = response.body.getReader();
      const chunks = []; let size = 0;
      while (true) {
        const part = await reader.read();
        if (part.done) break;
        size += part.value.byteLength; need(size <= 16384, 'SIZE'); chunks.push(part.value);
      }
      const bytes = new Uint8Array(size); let offset = 0;
      for (const chunk of chunks) { bytes.set(chunk, offset); offset += chunk.byteLength; }
      const wrapper = JSON.parse(new TextDecoder('utf-8', {fatal: true}).decode(bytes));
      need(object(wrapper) && Object.keys(wrapper).sort().join('|') === 'data|total' &&
        wrapper.total === fields.length, 'SHAPE');
      return validate(wrapper.data);
    } finally {
      controller.abort();
      if (reader) { try { await reader.cancel(); } catch (_) {} reader.releaseLock(); }
      clearTimeout(timer);
    }
  }
  try {
    need(location.origin === 'https://127.0.0.1', 'ORIGIN');
    const challenge = prompt('Paste the PUBLIC observation challenge printed by the waiting VM collector (not a password):');
    need(typeof challenge === 'string' && /^[a-f0-9]{64}$/.test(challenge), 'CHALLENGE');
    const first = await read();
    const second = await read();
    need(canonical(first) === canonical(second), 'DRIFT');
    // Only these fixed public facts leave memory, never the account body or
    // arbitrary tenant names, custom attributes, cookies or authorization.
    console.log(JSON.stringify({schema: 1, challenge, endpoint,
      source: 'dashboard-scoped-account', user_name_is_socanalyst: true,
      exact_indexer_role: true, backend_roles_empty: true, account_shape_version: 1,
      two_reads_equal: true, top_level_username_present: false,
      matches: {versioned_elastic_admin_predicate: findLiteral(first, 'username', 'elastic'),
        versioned_opensearch_admin_predicate: findLiteral(first, 'user_name', 'admin')},
      broker_run_as_body_observed: false, server_effective_policy_observed: false,
      mutation_authorized: false}));
  } catch (error) {
    const code = codes.has(error?.message) ? error.message : error?.name === 'AbortError' ? 'TIMEOUT' : 'UNEXPECTED';
    console.log('STOP Dashboard context: ' + code + '; no observation accepted; do not export raw responses');
  }
})();
