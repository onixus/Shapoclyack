FROM ghcr.io/onixus/pulse@sha256:70ab0ef673f1b49a9a52d8648999efb711dc0fa8e8cf81bab461e02dbf751ce2 AS pulse
FROM python:3.12-slim-bookworm@sha256:34386ef0cb081344d7ec1c103ba398e6e9f64e9ab3a1509accc92a4e24a07258
RUN apt-get update -qq && apt-get install -y -qq --no-install-recommends tcpdump libcap2-bin openssl && setcap cap_net_raw,cap_net_admin+eip /usr/bin/tcpdump && rm -rf /var/lib/apt/lists/*
COPY --from=pulse /pulse /usr/local/bin/pulse
RUN setcap cap_net_raw,cap_net_admin+eip /usr/local/bin/pulse
COPY requirements.lock /tmp/requirements.lock
RUN pip install --require-hashes -r /tmp/requirements.lock
