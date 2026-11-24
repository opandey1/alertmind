/* Separately reviewed/released Firefox lab-profile acceptance, NOT a login.
 * Fixed same-origin routes; no cookie/JWT/storage access, credentials or raw output.
 * The only write probe is a duplicate-name create of the already verified owned
 * rule. Its unique-name collision is fail-safe on v4.14.7, not a denial PASS.
 */
(async () => {
  'use strict';
  const codes = new Set(['ORIGIN', 'RELEASE', 'HOST', 'RESPONSE', 'SIZE', 'TIMEOUT',
    'ACCOUNT', 'POLICY', 'READ', 'DENIAL', 'DRIFT']);
  const need = (ok, code) => { if (!ok) throw new Error(code); };
  const object = x => x !== null && typeof x === 'object' && !Array.isArray(x);
  const canonical = x => JSON.stringify(object(x) ? Object.fromEntries(Object.keys(x).sort()
    .map(k => [k, JSON.parse(canonical(x[k]))])) : Array.isArray(x) ?
    x.map(v => JSON.parse(canonical(v))) : x);
  const role = 'alertmind_socanalyst_ro';
  const fields = ['user_name', 'is_reserved', 'is_hidden', 'is_internal_user',
    'user_requested_tenant', 'backend_roles', 'custom_attribute_names', 'tenants', 'roles'];
  const rule = {name: 'alertmind_socanalyst_server_ro', rule: {MATCH: {user_name: 'socanalyst'}}};
  const readonly = [
    [['agent:read'], ['agent:id:*', 'agent:group:*']],
    [['group:read'], ['group:id:*']],
    [['ciscat:read'], ['agent:id:*']],
    [['cluster:status', 'manager:read', 'manager:read_api_config'], ['*:*:*']],
    [['cluster:read_api_config', 'cluster:read'], ['node:id:*']],
    [['decoders:read'], ['decoder:file:*']],
    [['lists:read'], ['list:file:*']],
    [['rootcheck:read'], ['agent:id:*']],
    [['rules:read'], ['rule:file:*']],
    [['mitre:read'], ['*:*:*']],
    [['sca:read'], ['agent:id:*']],
    [['syscheck:read'], ['agent:id:*']],
    [['syscollector:read'], ['agent:id:*']]
  ];
  const expected = {rbac_mode: 'white'};
  for (const [actions, resources] of readonly) for (const action of actions) {
    expected[action] ??= {};
    for (const resource of resources) expected[action][resource] = 'allow';
  }
  async function request(endpoint, options = {}) {
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), 10000);
    let reader;
    try {
      const response = await fetch(endpoint, {...options, credentials: 'same-origin',
        cache: 'no-store', redirect: 'error', signal: controller.signal});
      need(response.url === location.origin + endpoint && response.type === 'basic' &&
        response.headers.get('Content-Type')?.split(';')[0].trim() === 'application/json', 'RESPONSE');
      reader = response.body.getReader();
      const chunks = []; let size = 0;
      while (true) {
        const part = await reader.read();
        if (part.done) break;
        size += part.value.byteLength; need(size <= 65536, 'SIZE'); chunks.push(part.value);
      }
      const bytes = new Uint8Array(size); let offset = 0;
      for (const chunk of chunks) { bytes.set(chunk, offset); offset += chunk.byteLength; }
      return {status: response.status, value: JSON.parse(new TextDecoder('utf-8', {fatal: true}).decode(bytes))};
    } finally {
      controller.abort();
      if (reader) { try { await reader.cancel(); } catch (_) {} reader.releaseLock(); }
      clearTimeout(timer);
    }
  }
  async function account() {
    const result = await request('/api/v1/configuration/account');
    const value = result.value?.data;
    need(result.status === 200 && result.value?.total === 9 && object(value) &&
      Object.keys(value).sort().join('|') === fields.slice().sort().join('|') &&
      value.user_name === 'socanalyst' && value.is_internal_user === true &&
      value.is_reserved === false && value.is_hidden === false &&
      Array.isArray(value.roles) && canonical(value.roles) === canonical([role]) &&
      Array.isArray(value.backend_roles) && value.backend_roles.length === 0 &&
      Array.isArray(value.custom_attribute_names) && value.custom_attribute_names.length === 0, 'ACCOUNT');
    return value;
  }
  async function broker(host, method, path, body = null) {
    // devTools preserves the upstream HTTP status and detail message.
    // Dashboard's response adapter replaces the numeric Server error.
    return request('/api/request', {method: 'POST', headers: {
      'Content-Type': 'application/json', 'osd-xsrf': 'alertmind-readonly-acceptance'},
      body: JSON.stringify({id: host, method, path, body: {
        devTools: true, ...(body === null ? {} : {body})}})});
  }
  function success(result) {
    need(result.status === 200 && result.value?.error === 0 && object(result.value.data), 'READ');
    return result.value.data;
  }
  function denied(result) {
    const body = result.value;
    need(result.status === 403 && object(body) && Object.keys(body).length === 3 &&
      body.statusCode === 403 && body.error === 'Forbidden' &&
      body.message === 'Permission denied: Resource type: *:*', 'DENIAL');
  }
  try {
    need(location.origin === 'https://127.0.0.1', 'ORIGIN');
    need(prompt('Type RELEASED-SAFE-ACCEPTANCE only after fresh operator check, existing rule verified, no concurrent maintenance and separate approval:')
      === 'RELEASED-SAFE-ACCEPTANCE', 'RELEASE');
    const host = prompt('PUBLIC Server host ID from the single reviewed wazuh.yml entry (not a credential):');
    need(typeof host === 'string' && /^[A-Za-z0-9_-]{1,64}$/.test(host), 'HOST');
    const first = await account();
    const policy = success(await broker(host, 'GET', '/security/users/me/policies'));
    need(canonical(policy) === canonical(expected), 'POLICY');
    const agents = success(await broker(host, 'GET', '/agents?limit=1&select=id'));
    need(agents.total_failed_items === 0 && Array.isArray(agents.failed_items) &&
      agents.failed_items.length === 0 && Number.isInteger(agents.total_affected_items) &&
      agents.total_affected_items > 0 && Array.isArray(agents.affected_items) &&
      agents.affected_items.length === 1 && /^\d{3}$/.test(agents.affected_items[0]?.id), 'READ');
    // The rules list can return HTTP 200 with zero visible items. The
    // resourceless security configuration read gives an explicit denial.
    denied(await broker(host, 'GET', '/security/config'));
    denied(await broker(host, 'POST', '/security/rules', rule));
    const again = success(await broker(host, 'GET', '/security/users/me/policies'));
    need(canonical(again) === canonical(expected) && canonical(first) === canonical(await account()), 'DRIFT');
    console.log(JSON.stringify({schema: 2, source: 'actual-dashboard-as-current-user',
      socanalyst_account_verified: true, effective_readonly_policy_exact: true,
      bounded_server_agent_read: true, security_config_read_http: 403,
      duplicate_rule_create_http: 403, dashboard_denial_detail_matched: true,
      account_and_policy_equal_before_after: true, direct_run_as_used: false,
      real_agent_action_sent: false, indexer_grants_changed: false,
      requires_post_probe_operator_check: true, phase1_complete: false}));
  } catch (error) {
    const code = codes.has(error?.message) ? error.message : error?.name === 'AbortError' ? 'TIMEOUT' : 'UNEXPECTED';
    console.log('STOP human acceptance: ' + code + '; no acceptance claimed; do not export raw responses');
  }
})();
