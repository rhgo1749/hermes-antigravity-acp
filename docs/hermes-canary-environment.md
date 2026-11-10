# Optional Hermes canary environment

This note describes an optional host-integration test boundary. It is not
required by the generic ACP installer or provider.

The helper in `scripts/hermes_canary_env.py` builds an environment for a selected
Hermes profile under a `.hermes` state directory. It distinguishes the profile's
child-process home from the parent home used by an explicitly configured ACP
multiplexer. The generic installer does not set `HERMES_REAL_HOME` or
`ACP_MUX_HOME`, select an account, or read a multiplexer registry.

`tests/test_hermes_canary_env.py` uses synthetic temporary paths to check this
environment mapping. It does not open credential files, authenticate, or contact
an ACP server. Passing this test verifies path resolution only; it is not
evidence of live authentication, account availability, or deployment state.
