FROM python:3.11-slim-buster as python-base

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PIP_NO_CACHE_DIR=off \
    PIP_DISABLE_PIP_VERSION_CHECK=on \
    PIP_DEFAULT_TIMEOUT=100

ENV PATH="/opt/venv/bin:$PATH"

FROM python-base as builder-base
RUN apt-get update \
 && apt-get install -y gcc git

RUN python -m venv /opt/venv
COPY ./requirements.txt .
RUN pip install --no-cache-dir --upgrade pip \
 && pip install --no-cache-dir setuptools wheel \
 && pip install --no-cache-dir -r requirements.txt

FROM python-base as production
COPY --from=builder-base /opt/venv /opt/venv
RUN apt-get update && apt-get install -y curl

WORKDIR /app
COPY ./src /app/src

CMD ["python", "-m", "src"]
