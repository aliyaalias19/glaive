# GLAIVE web app in a container.
#   docker build -t glaive .
#   docker run -p 8765:8765 -v "$PWD/cases:/cases" --env-file .env glaive
#
# Every dependency ships prebuilt wheels for Linux, so no compiler is needed.
FROM python:3.12-slim
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1
WORKDIR /app
COPY pyproject.toml README.md LICENSE ./
COPY glaive ./glaive
RUN pip install --no-cache-dir ".[fast]"
RUN useradd --create-home glaive && mkdir /cases && chown glaive /cases
USER glaive
VOLUME ["/cases"]
EXPOSE 8765
# Listening on 0.0.0.0 makes GLAIVE require an access token (set GLAIVE_WEB_TOKEN,
# or read the generated one from `docker logs`).
CMD ["glaive", "serve", "/cases/case", "--host", "0.0.0.0", "--port", "8765", "--no-browser"]
