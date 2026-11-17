# Authorized recon toolkit. Active scanners are not installed in this image.
FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1

WORKDIR /opt/bbtk
COPY pyproject.toml README.md ./
COPY bugbounty_toolkit ./bugbounty_toolkit
COPY skills ./skills

RUN pip install --no-cache-dir .

WORKDIR /work
ENTRYPOINT ["bbtk"]
CMD ["--help"]
