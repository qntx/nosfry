# Operator guides

| Guide                                  | What it covers                                                                                                                                                             |
| -------------------------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| [install.md](install.md)               | Release binaries and their glibc floor, verifying checksums and attestations, the container image, building from source, the first start.                                  |
| [configuration.md](configuration.md)   | Every configuration key with its default and reload behaviour, a minimal public configuration, and the behaviour behind the keys.                                          |
| [deployment.md](deployment.md)         | A production checklist, the hardened systemd unit, open-file limits, nginx with TLS, rate limiting and the client address, containers, monitoring and alerts, a full disk. |
| [administration.md](administration.md) | The `export`, `import`, `scan`, `delete` and `compact` commands, the NIP-86 management API, backup and restore, upgrading between versions, retention.                     |
| [sync.md](sync.md)                     | `nosfry sync`: mirroring, backfilling and two-way sync with another relay over NIP-77, exit codes, limits, authentication, URL rules.                                     |
| [security.md](security.md)             | Trust boundaries, every enforced bound, the known gaps, a recommended public profile.                                                                                      |
| [tor.md](tor.md)                       | Serving the relay as an onion service with C tor, and the limits of that setup.                                                                                            |
| [workers.md](workers.md)               | The Cloudflare Workers edition (preview): build, configure, run locally, deploy.                                                                                           |
| [test-relay.md](test-relay.md)         | A pinned, seeded, resettable relay for client integration tests and CI.                                                                                                    |

The files these guides refer to are in [`contrib/`](../contrib):
`contrib/systemd/nosfry.service` and `contrib/nginx/nosfry.conf`.
