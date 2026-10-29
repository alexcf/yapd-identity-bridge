FROM python:3.12-slim-bookworm@sha256:e697c81897302a4c4333bade000d98038fbb21eb064f8ee1fd42d02ebcd9d337
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1
WORKDIR /app
COPY bridge.py client.py healthcheck.py daemon.py ./
COPY providers ./providers
COPY collectors ./collectors
COPY triggers ./triggers
USER 1000:1000
HEALTHCHECK --interval=60s --timeout=5s --start-period=60s --retries=3 CMD ["python", "healthcheck.py"]
CMD ["python", "bridge.py", "--apply", "--daemon"]
