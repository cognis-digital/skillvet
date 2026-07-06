# skillvet — the trust gate for agent skills. Stdlib-only core, so the image is tiny.
# Build:  docker build -t skillvet .
# Use:    docker run --rm -v "$PWD/some-skill:/scan:ro" skillvet vet /scan
#         docker run --rm -v "$PWD/some-skill:/scan:ro" skillvet vet /scan -f sarif
FROM python:3.12-slim

WORKDIR /app
COPY pyproject.toml README.md LICENSE ./
COPY skillvet ./skillvet
RUN pip install --no-cache-dir .

# Run as non-root; the scanner never needs to write to the package it reads.
RUN useradd -m -u 10001 vet
USER vet

WORKDIR /scan
ENTRYPOINT ["skillvet"]
CMD ["--help"]
