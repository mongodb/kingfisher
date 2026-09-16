# syntax=docker/dockerfile:1
FROM alpine:latest@sha256:25109184c71bdad752c8312a8623239686a9a2071e8825f20acb8f2198c3f659

RUN apk add --no-cache curl tar git

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
    LATEST_URL=$(curl -fsSL "https://api.github.com/repos/mongodb/kingfisher/releases/tags/v${KINGFISHER_VERSION}" \
        | grep -Eo "https://[^\"]*${SUFFIX}"); \
    if [ -z "$LATEST_URL" ]; then \
        echo "Failed to fetch the latest release URL for ${SUFFIX}" >&2; \
        exit 1; \
    fi; \
    curl -fsSL "$LATEST_URL" -o kingfisher.tgz; \
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
