# Control plane: the out-of-band tool-poisoning scanning worker.
#
# Mirrors gateway/Dockerfile's shape (multi-stage, non-root uid 10001) but
# not its slimness: sentence-transformers pulls in torch, so this image is
# large by nature. The model weights (~90MB) are baked in at build time
# rather than downloaded on first use, so a worker started in a network-
# restricted environment still scans instead of failing on its first job.
FROM python:3.12-slim AS build

WORKDIR /src
RUN apt-get update \
 && apt-get install -y --no-install-recommends build-essential \
 && rm -rf /var/lib/apt/lists/*

COPY pyproject.toml ./
COPY scanner ./scanner
# Install into a virtualenv so the runtime stage copies one self-contained
# directory rather than picking through site-packages.
RUN python -m venv /opt/venv
ENV PATH="/opt/venv/bin:$PATH"
RUN pip install --no-cache-dir .

# Pre-download the embedding model so the first scan does not depend on
# reaching the Hugging Face Hub.
RUN python -c "from sentence_transformers import SentenceTransformer; SentenceTransformer('all-MiniLM-L6-v2')"

FROM python:3.12-slim

RUN adduser --disabled-password --gecos '' --uid 10001 portcullis

COPY --from=build /opt/venv /opt/venv
# The cached model weights live in the build stage's HOME; carry them over
# and hand them to the runtime user.
COPY --from=build --chown=portcullis:portcullis /root/.cache /home/portcullis/.cache

WORKDIR /app
COPY --chown=portcullis:portcullis scanner ./scanner
COPY --chown=portcullis:portcullis evals ./evals
COPY --chown=portcullis:portcullis app ./app

ENV PATH="/opt/venv/bin:$PATH" \
    PYTHONUNBUFFERED=1 \
    HOME=/home/portcullis

USER portcullis
ENTRYPOINT ["python", "-m", "app.run_worker"]
