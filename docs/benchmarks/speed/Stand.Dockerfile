# The speed-benchmark runtime for a test stand: the released scanner image as
# shipped, plus only what the harness and the comparison need. libpcap0.8 is
# the Debian package a SYN fix would add to the image (#594); installing it
# here is what tests that fix, not the PyPI build the cloud runs used.
ARG SCANNER_IMAGE=ghcr.io/onixus/shapoclyack-scanner:shapoclyack-0.48-1021@sha256:395ba59100a425c3a2a1a0e1420d42965c07e56d222bee53b21b618742fa526e

# The released image ships without pip, so pyroute2 (pure Python) is
# installed in a throwaway stage and copied onto PYTHONPATH.
FROM python:3.12-slim AS pydeps
RUN python -m pip install --no-cache-dir --target /opt/bench-pydeps 'pyroute2==0.9.6'

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
