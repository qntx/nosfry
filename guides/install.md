# Install

## Release binaries

Every [GitHub release](https://github.com/qntx/nosfry/releases) from 0.4.0 on
carries these archives:

| Archive                                             | Runs on                            |
| --------------------------------------------------- | ---------------------------------- |
| `nosfry-<version>-x86_64-unknown-linux-gnu.tar.gz`  | Linux x86_64, glibc 2.31 or newer  |
| `nosfry-<version>-aarch64-unknown-linux-gnu.tar.gz` | Linux aarch64, glibc 2.31 or newer |
| `nosfry-<version>-aarch64-apple-darwin.tar.gz`      | macOS on Apple silicon             |

glibc 2.31 means Debian 11, Ubuntu 20.04, RHEL 9 or newer. The release
workflow starts every Linux binary in Debian 11, Debian 12 and Ubuntu 22.04
containers before it publishes. The 0.3.0 and older Linux binaries need glibc
2.38 and do not start on Debian 12 or Ubuntu 22.04. There is no musl or Windows
build; nosfry relies on the system allocator, and glibc's is the one the
benchmarks measured.

Each archive holds `nosfry`, `nosfry.example.toml`, `README.md`,
`CHANGELOG.md` and the licenses, and comes with a `.sha256` file, a CycloneDX
SBOM (`.cdx.json`) and GitHub build provenance attestations:

```bash
VERSION=0.4.0 TARGET=x86_64-unknown-linux-gnu
curl -fsSLO "https://github.com/qntx/nosfry/releases/download/v$VERSION/nosfry-$VERSION-$TARGET.tar.gz"
curl -fsSLO "https://github.com/qntx/nosfry/releases/download/v$VERSION/nosfry-$VERSION-$TARGET.tar.gz.sha256"
sha256sum -c "nosfry-$VERSION-$TARGET.tar.gz.sha256"
gh attestation verify "nosfry-$VERSION-$TARGET.tar.gz" --repo qntx/nosfry
tar xzf "nosfry-$VERSION-$TARGET.tar.gz"
sudo install -m 0755 "nosfry-$VERSION-$TARGET/nosfry" /usr/local/bin/nosfry
nosfry --version
```

On macOS use `shasum -a 256 -c` instead of `sha256sum -c`.

## Container image

`ghcr.io/qntx/nosfry` is published for `linux/amd64` and `linux/arm64` with the
tags `<version>`, `<major>.<minor>`, `<major>` and `latest`. It is a distroless,
non-root image: the binary is `/nosfry`, the configuration is
`/etc/nosfry/nosfry.toml` (`NOSFRY_CONFIG`), and the database lives in the
volume `/data`.

```bash
docker run -d --name nosfry \
    -p 127.0.0.1:7777:7777 \
    -v nosfry-data:/data \
    --ulimit nofile=1000000:1000000 \
    --stop-timeout 60 \
    ghcr.io/qntx/nosfry:latest
gh attestation verify oci://ghcr.io/qntx/nosfry:latest --repo qntx/nosfry
```

The bundled configuration only sets `db.path = "/data/nosfry-db"` and
`relay.bind = "0.0.0.0"`. To change anything else, mount your own file over
`/etc/nosfry/nosfry.toml` and keep those two keys:

```bash
docker run -d --name nosfry \
    -p 127.0.0.1:7777:7777 \
    -v nosfry-data:/data \
    -v "$PWD/nosfry.toml:/etc/nosfry/nosfry.toml:ro" \
    ghcr.io/qntx/nosfry:latest
```

The image has no shell, so the relay refuses to start with a write-policy
plugin configured (`relay.write_policy.plugin needs /bin/sh`). To run a
plugin, copy the binary into an image that has the plugin's interpreter:

```dockerfile
FROM debian:bookworm-slim
RUN apt-get update && apt-get install -y --no-install-recommends python3 && rm -rf /var/lib/apt/lists/*
COPY --from=ghcr.io/qntx/nosfry:latest /nosfry /usr/local/bin/nosfry
COPY policy.py nosfry.toml /etc/nosfry/
ENV NOSFRY_CONFIG=/etc/nosfry/nosfry.toml
VOLUME ["/data"]
ENTRYPOINT ["nosfry"]
CMD ["relay"]
```

## From source

```bash
cargo install nosfry --locked
```

This needs Rust 1.99 or newer and a C compiler (LMDB and libsecp256k1 are C
libraries built by cargo).

## First start

```bash
cp nosfry.example.toml nosfry.toml
nosfry relay
```

`nosfry` reads `--config <path>`, else `$NOSFRY_CONFIG`, else `./nosfry.toml`.
The example configuration listens on `127.0.0.1:7777` and creates the database
in `./nosfry-db`. Logs go to stderr (`RUST_LOG`, JSON with `RUST_LOG_JSON=1`).
Continue with [deployment.md](deployment.md) before the relay faces the
internet.
