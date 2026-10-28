# Security policy

* Decoy tokens are generated at plant time and are **non-functional**. Never commit the `--state` directory or planted workspaces (see `.gitignore`).
* The decoy server must run isolated: no outbound network, read-only filesystem, all capabilities dropped (see `docker-compose.yml`). It never proxies or executes input.
* Don't plant decoys that reuse real credential material or that grant any real access.
* Use only on systems you own or are authorized to defend.

Report vulnerabilities privately via GitHub Security Advisories on this repository.
