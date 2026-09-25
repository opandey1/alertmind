# Guard Python runtime trust — offline inventory boundary

Status: **not selected, not installed, not approved for startup**. This records
the next evidence required for the dormant held-code loader; it does not ask
for a VM command or authorize a Dashboard change.

The 13 source files in the proposed pre-start capsule have an exact, CI-checked
direct-import contract. Their module bodies import these 16 standard-library
roots: `base64`, `binascii`, `contextlib`, `dataclasses`, `errno`, `hashlib`,
`json`, `os`, `pathlib`, `re`, `selectors`, `stat`, `subprocess`, `sys`, `time`,
and `types`. `operator_fs._identity()` later imports `pwd` and `grp`, making
**18 direct roots in the full possible call path**. Relative project imports
refer only to earlier, pinned modules. The contract also catches recognized
`__import__`, `eval`, `exec` and `importlib`/`runpy`-style calls in these
sources. This is static source coverage, not a Python sandbox: aliasing,
transitive imports, C extensions and runtime-loaded modules are not proven.

Before executing the dormant loader in any pre-start path, an independent
review must settle all of the following from a **selected host runtime**:

1. The exact interpreter executable and its resolved target, version,
   installation/package provenance, bytes and non-service-writable ownership
   chain. The historical Wazuh-packaged Python path is only a candidate, not
   a selected or trusted interpreter.
2. The exact launch command and environment, including `-I -S -B`, linker
   inputs and path-related variables. An observed `sys.flags` value is a
   post-start tripwire, not authentication of what ran before the guard's
   first line. The unit policy must establish these inputs externally.
3. The selected runtime's effective `sys.path`, `sys.meta_path`, preloaded
   `sys.modules`, extension-module origins and standard-library provenance,
   including transitively imported code for all 18 direct roots. A source
   import list alone is not a full dependency closure.
4. An independently approved pin/update policy for those runtime artifacts
   and a recovery plan for package upgrades. A manifest derived from the
   running interpreter's own report cannot by itself attest that interpreter.
5. Native Linux/Python-version tests of the exact candidate, plus review of
   import side effects and startup latency. Existing Windows Python 3.12
   tests establish only the offline source contract.

Python's [isolated mode and site flags](https://docs.python.org/3.10/using/cmdline.html)
exclude several common injection paths, but do not certify the interpreter
or standard-library files. Python's [import system](https://docs.python.org/3.10/reference/import.html)
uses cached modules and finders; these also need review. Until the above is
accepted, `operator_guard_entry.py` must continue to **compile only**, exit 1,
and remain absent from the Dashboard service. Human `socanalyst` and broker
acceptance remain separate later gates.
