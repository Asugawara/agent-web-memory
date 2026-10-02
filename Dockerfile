# awm server image (plan-v3-team §3.9.1 path D): one distroless, non-root container that runs
# `awm serve` with its own TLS. Build: docker build -t awm:dev .
#
# The configuration comes from the environment (AWM_DOMAIN, AWM_BACKUP, AWM_BEHIND_TLS_PROXY,
# AWM_TRUSTED_PROXY, AWM_ACME_*), see deploy/compose/env.example and docs/self-host.md.
# Without AWM_DOMAIN or AWM_BEHIND_TLS_PROXY the server refuses to start (exit 2): a public
# listener never serves plain HTTP.

FROM rust:1.97.1-bookworm AS builder
WORKDIR /src
COPY . .
RUN cargo build --release --locked --features sync,serve -p agent-web-memory
# The state directory, owned by the runtime user (distroless "nonroot" is uid/gid 65532) so that
# a named volume mounted at /data starts with the right owner. Mode 0700 as `awm serve` expects.
RUN mkdir /data && chmod 0700 /data && chown 65532:65532 /data

FROM gcr.io/distroless/cc-debian12:nonroot
COPY --from=builder /src/target/release/awm /usr/local/bin/awm
COPY --from=builder --chown=65532:65532 /data /data
COPY LICENSE THIRD_PARTY_LICENSES.md /licenses/

# AWM_DATA and AWM_LISTEN are read by `awm serve` and by `awm serve healthcheck` alike (the
# health check does not see the command line, only the environment). 8443 inside is published as
# 443 (TLS-ALPN-01 needs the CA to reach the host's 443); a non-root process needs no capability
# above 1024. For HTTP-01 also set AWM_ACME_CHALLENGE=http-01 and AWM_ACME_HTTP_LISTEN=0.0.0.0:8080
# and publish 80:8080.
ENV AWM_DATA=/data \
    AWM_LISTEN=0.0.0.0:8443

USER 65532:65532
VOLUME ["/data"]
EXPOSE 8443 8080

# Exit 0 when /healthz answers 200 on the local listener (https on loopback when AWM_DOMAIN is
# set, http behind a TLS proxy); the scheme and port come from the same environment as `serve`.
HEALTHCHECK --interval=30s --timeout=5s --start-period=60s --retries=3 \
    CMD ["/usr/local/bin/awm", "serve", "healthcheck"]

ENTRYPOINT ["awm"]
CMD ["serve"]
