# Reproducible local-only acceptance runtime; never scan external targets.
FROM golang:1.26-bookworm AS engine
RUN GOBIN=/out go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@v3.11.1
FROM python:3.12-slim-bookworm
RUN pip install --no-cache-dir PyYAML==6.0.3 pydantic==2.12.3
COPY --from=engine /out/nuclei /fixture-bin/nuclei
WORKDIR /work
ENV PYTHONPATH=/work
ENTRYPOINT ["python", "scripts/benchmark-nuclei-catalog.py"]
