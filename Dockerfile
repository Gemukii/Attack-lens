FROM python:3.12-slim-trixie@sha256:b18b261e1b4974b4f321451ad5251ded85abb22c2b8b262da527dda1d031ab30

WORKDIR /app

ENV PYTHONDONTWRITEBYTECODE=1 \
	PYTHONUNBUFFERED=1 \
	PIP_NO_CACHE_DIR=1

COPY pyproject.toml requirements.lock ./
COPY src ./src

RUN apt-get update \
	&& apt-get upgrade -y --no-install-recommends \
	&& rm -rf /var/lib/apt/lists/* \
	&& python -m pip install --no-cache-dir --upgrade pip \
	&& python -m pip install --no-cache-dir --require-hashes -r requirements.lock \
	&& python -m pip install --no-cache-dir --no-deps . \
	&& rm -rf /root/.cache/pip /tmp/* /root/.cache

RUN addgroup --gid 10001 attacklens \
	&& adduser --uid 10001 --gid 10001 --home /app --no-create-home --disabled-login --gecos "" attacklens \
	&& mkdir -p /app/data /app/results /app/backups \
	&& chown -R attacklens:attacklens /app

USER attacklens

EXPOSE 8000

CMD ["uvicorn", "attacklens.web.api:app", "--host", "0.0.0.0", "--port", "8000"]