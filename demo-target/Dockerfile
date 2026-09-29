# The demo target lab (docs/BUILD_SPEC.md §19, §2.4).
#
# One image, three services, selected by the command. It carries no credential,
# installs nothing that reaches a network at runtime, and runs as a non-root
# user with no ability to write outside /tmp — the app is meant to be exploited,
# so the blast radius of exploiting it is part of the design.
FROM python:3.12-slim

# Intentionally vulnerable: labelled so an image scanner and a human both see
# it before anything is deployed anywhere.
LABEL org.opencontainers.image.title="Kervy demo target (intentionally vulnerable)"
LABEL org.opencontainers.image.description="Do not deploy. Built to be exploited."
LABEL com.kervy.intentionally-vulnerable="true"

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    # The container has to bind every interface to be reachable from the worker
    # on the compose network. That network is declared `internal: true`, so
    # there is no route off the host.
    LAB_HOST=0.0.0.0

WORKDIR /lab

# Pinned, and deliberately tiny: the lab needs a web server and nothing else.
RUN pip install --no-cache-dir "fastapi>=0.115,<1" "uvicorn>=0.32,<1"

COPY lab/ /lab/lab/

RUN useradd --create-home --shell /usr/sbin/nologin labuser \
    && chown -R labuser:labuser /lab
USER labuser

# No default service: "run the lab" is a question, not an instruction.
ENTRYPOINT ["python", "-m", "lab.main"]
