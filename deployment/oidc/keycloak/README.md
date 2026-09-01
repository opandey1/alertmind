# Local Keycloak deployment scaffold

This directory will hold a secret-free template for the opt-in authenticated
AlertMind analyst profile.

**Current status:** Phase 0 scaffold only. Keycloak is not installed or running,
and no realm, client, user, group or secret has been created by this work.

The later template will define placeholders for:

- a local realm and confidential Streamlit client;
- an exact redirect URI and post-logout redirect URI;
- issuer and audience validation;
- a single unambiguous `soc-analyst` group/role mapping; and
- short session/token lifetimes suitable for the isolated lab.

The OIDC client secret and all generated runtime data stay local. They belong
in ignored paths such as `assistant/.streamlit/secrets.toml` and
`deployment/oidc/keycloak/data/`, never in `realm-template.json`, screenshots,
logs or Git history.

Installation and realm export are deferred until the owner approves the local
IdP choice and the Phase 0 Wazuh inventory passes review.
