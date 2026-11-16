# syntax=docker/dockerfile:1
FROM alpine:latest@sha256:be2656061b536c1883c4034790e21d0a09c5aaaf51968b89368a3c0371ea2c9a

RUN apk add --no-cache ca-certificates curl openssh-client tar

ARG TARGETARCH
ARG KINGFISHER_VERSION
ENV TARGETARCH=${TARGETARCH}

WORKDIR /app

RUN set -eux; \
    # choose the right asset for this build platform
    case "${TARGETARCH}" in \
        amd64) SUFFIX="linux-x64.tgz"  ;; \
        arm64) SUFFIX="linux-arm64.tgz" ;; \
        *)     echo "unsupported arch ${TARGETARCH}" >&2; exit 1 ;; \
    esac; \
    # download & unpack
    test -n "${KINGFISHER_VERSION}"; \
    apk add --no-cache --virtual .kingfisher-fetch jq; \
    ASSET="kingfisher-${SUFFIX}"; \
    RELEASE_JSON=$(curl -fsSL "https://api.github.com/repos/mongodb/kingfisher/releases/tags/v${KINGFISHER_VERSION}"); \
    ASSET_URL=$(printf '%s' "$RELEASE_JSON" \
        | jq -er --arg name "$ASSET" '.assets[] | select(.name == $name) | .browser_download_url'); \
    # GitHub publishes a SHA-256 digest for each release asset; refuse unverified archives.
    ASSET_SHA256=$(printf '%s' "$RELEASE_JSON" \
        | jq -er --arg name "$ASSET" '.assets[] | select(.name == $name) | .digest | select(startswith("sha256:")) | ltrimstr("sha256:")'); \
    curl -fsSL "$ASSET_URL" -o kingfisher.tgz; \
    test "$(sha256sum kingfisher.tgz | cut -d ' ' -f 1)" = "$ASSET_SHA256"; \
    apk del .kingfisher-fetch; \
    tar -xzf kingfisher.tgz; \
    rm -f kingfisher.tgz CHECKSUM-*.txt; \
    # locate the binary (pattern covers kingfisher-linux-x64 / kingfisher-linux-arm64)
    KF_PATH=$(find . -type f -name 'kingfisher*' -executable -print -quit); \
    if [ -z "$KF_PATH" ]; then echo "No executable kingfisher binary found" >&2; exit 1; fi; \
    install -m 0755 "$KF_PATH" /usr/local/bin/kingfisher; \
    # optional cleanup to keep the image small
    rm -rf /app/*

RUN addgroup -S -g 10001 app \
    && adduser -S -D -H -u 10001 -G app -h /app app \
    && install -d -o app -g app /app /var/lib/kingfisher

USER 10001:10001

# quick smoke-test so the build fails early if something’s wrong
RUN kingfisher --version

ENTRYPOINT ["kingfisher"]
