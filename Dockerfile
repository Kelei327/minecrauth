# Ref: https://github.com/GoogleContainerTools/distroless/tree/main/static
#
# GoReleaser builds the per-platform binaries outside the image and places them
# under linux/<arch>/ in the Docker build context (via builds hooks + extra_files).
# Docker Buildx automatically sets the ARG TARGETPLATFORM to the platform it is
# building for (e.g. linux/amd64, linux/arm64), which makes the COPY instructions
# below select the correct pre-built binary without any conditional logic.
#
# distroless/static:nonroot is chosen over scratch because:
#   - it provides CA certificates (OIDC fallback makes outbound HTTPS calls), and
#   - it runs as a non-root user (UID 65532) out of the box.
# The Go binary is fully static (CGO_ENABLED=0), so no libc is needed.
FROM gcr.io/distroless/static:nonroot

ARG TARGETPLATFORM

# Static OCI metadata. Dynamic fields (version, created, revision) are injected
# by GoReleaser at build time via --label flags in build_flag_templates.
# Ref: https://github.com/opencontainers/image-spec/blob/main/annotations.md
LABEL org.opencontainers.image.title="minecrauth" \
      org.opencontainers.image.description="Self-hostable Yggdrasil-compatible Minecraft authentication server" \
      org.opencontainers.image.url="https://github.com/achetronic/minecrauth" \
      org.opencontainers.image.source="https://github.com/achetronic/minecrauth" \
      org.opencontainers.image.licenses="Apache-2.0"

# Copy the server binary. Administration is done entirely through the HTTP API
# (and the embedded Web UI), so no separate CLI binary ships in the image.
COPY ${TARGETPLATFORM}/minecrauth /usr/local/bin/minecrauth

# Mount a volume here for the SQLite database and signing key.
# The nonroot user (UID 65532) must have write access to this path on the host.
VOLUME ["/data"]

# Default Yggdrasil/authlib-injector port. Set the listen address via listen_addr in the config file.
EXPOSE 25585

ENTRYPOINT ["/usr/local/bin/minecrauth"]

# The operator must provide the configuration file (e.g., mount it at /config/config.yaml).
CMD ["--config", "/config/config.yaml"]
