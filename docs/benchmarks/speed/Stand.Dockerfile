# The speed-benchmark runtime for a test stand: the released scanner image as
# shipped, plus only what the harness and the comparison need. libpcap0.8 is
# the Debian package a SYN fix would add to the image (#594); installing it
# here is what tests that fix, not the PyPI build the cloud runs used.
ARG SCANNER_IMAGE=ghcr.io/onixus/shapoclyack-scanner:shapoclyack-0.48-1021@sha256:395ba59100a425c3a2a1a0e1420d42965c07e56d222bee53b21b618742fa526e

# The released image ships without pip, so pyroute2 (pure Python) is
# installed in a throwaway stage and copied onto PYTHONPATH. The base and the
# wheel are pinned like the product images' (Dockerfile): same digest, hashes.
FROM python:3.12-slim@sha256:dddfd7e07f9d15aeeca61529320492139d21cac7f0070c00609243e51e4e0016 AS pydeps
RUN set -eux; \
    echo 'pyroute2==0.9.6 --hash=sha256:3334091326e560a506635449af03b26920d22d4e5a7996aed354363d106fcef8' \
        > /tmp/bench-pydeps.txt; \
    python -m pip install --no-cache-dir --require-hashes --only-binary=:all: \
        --target /opt/bench-pydeps -r /tmp/bench-pydeps.txt

FROM ${SCANNER_IMAGE}
USER root
RUN set -eux; \
    apt-get update; \
    apt-get install -y --no-install-recommends libpcap0.8 masscan util-linux; \
    rm -rf /var/lib/apt/lists/*; \
    command -v naabu nsenter masscan
COPY --from=pydeps /opt/bench-pydeps /opt/bench-pydeps
ENV PYTHONPATH=/opt/bench-pydeps
RUN python -c 'import pyroute2'
USER scanner
ENTRYPOINT ["python", "/bench/benchmark-speed.py"]
