# Contributing to Egressy

Thanks for improving Egressy. This project changes routing and firewall state,
so correctness and reproducible evidence matter more than patch size.

Before opening a change, read `AGENTS.md`, `docs/ARCHITECTURE.md`,
`docs/NETWORKING.md`, and `docs/SECURITY.md`. Discuss intentional CLI, YAML,
label, JSON, or networking compatibility breaks before implementation.

For every change:

1. add focused unit or integration coverage;
2. update the OpenAPI contract and dashboard types when API semantics change;
3. run the checks in `docs/TESTING.md`;
4. keep host-network tests confined to a disposable environment;
5. scan the proposed commits for credentials and private infrastructure;
6. explain operational and rollback impact in the pull request.

Use fake keys and documentation-only addresses in fixtures. Do not include AI
co-author metadata, generated credentials, raw public source observations, or
complete WireGuard profiles.

By contributing, you agree that your contribution is licensed under the
repository's AGPL-3.0-only license.
