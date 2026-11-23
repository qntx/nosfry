
## Verifying the artifacts

Every archive has a `.sha256` file (all of them are also in `SHA256SUMS`),
a build provenance attestation, and a CycloneDX SBOM (`.cdx.json`) attested
to the archive it describes. The container image carries its own provenance
attestation and SBOM. The same applies to the `nosfry-<version>-onion-<target>`
archives and the `ghcr.io/qntx/nosfry:<version>-onion` image tags, which ship
the Arti-linked variant.

```bash
sha256sum -c nosfry-<version>-<target>.tar.gz.sha256
gh attestation verify nosfry-<version>-<target>.tar.gz --repo qntx/nosfry
gh attestation verify oci://ghcr.io/qntx/nosfry:<version> --repo qntx/nosfry
```

The Linux binaries need glibc 2.31 or newer (Debian 11, Ubuntu 20.04, RHEL 9
and newer); each one was started on Debian 11, Debian 12 and Ubuntu 22.04
before this release was published.
