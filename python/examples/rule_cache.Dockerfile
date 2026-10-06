# Build from the repository root with one compatible, repaired SDK wheel:
# docker build -f python/examples/rule_cache.Dockerfile \
#   --build-arg SDK_WHEEL=dist-python/your-compatible-wheel.whl -t kingfisher-cache-demo .
# Deploy this same image on another host; the SDK and engine build remain identical.
ARG PYTHON_IMAGE=python:3.13-slim
FROM ${PYTHON_IMAGE} AS sdk
ARG SDK_WHEEL
COPY ${SDK_WHEEL} /tmp/wheels/
RUN python -m pip install --no-cache-dir /tmp/wheels/*.whl \
    && rm -rf /tmp/wheels
ENV KF_RULE_CACHE_DIR=/opt/kingfisher/rule-cache \
    PYTHONDONTWRITEBYTECODE=1

# Image construction runs as root. Match the service's catalog and confidence.
FROM sdk AS cache-builder
RUN python -c 'from kingfisher_sdk import Rules; rules = Rules(confidence="medium"); assert rules.cache_status == "stored", rules.cache_status'

FROM sdk AS runtime
RUN install -d -m 0700 -o 10001 -g 10001 /opt/kingfisher/rule-cache
# File ownership belongs to the deployed service, independent of the builder's UID.
# The explicit destination is private; COPY preserves entry modes (0600).
COPY --from=cache-builder --chown=10001:10001 /opt/kingfisher/rule-cache /opt/kingfisher/rule-cache
COPY python/examples/rule_cache.py /opt/kingfisher/rule_cache.py
USER 10001:10001
ENTRYPOINT ["python", "/opt/kingfisher/rule_cache.py"]
# On compatible hosts, --require-hit can verify image prewarming even with
# docker run --rm --read-only kingfisher-cache-demo --require-hit
# Ordinary startup allows CPU incompatibility to trigger local recompilation.
