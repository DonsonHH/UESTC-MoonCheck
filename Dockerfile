ARG PYTHON_BASE_IMAGE=python:3.12-slim-bookworm
FROM ${PYTHON_BASE_IMAGE}
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 TZ=Asia/Shanghai
WORKDIR /app
COPY requirements.txt ./
RUN python -m pip install --no-cache-dir --only-binary=:all: -r requirements.txt
COPY moonuestc ./moonuestc
COPY tests ./tests
COPY LICENSE THIRD_PARTY_NOTICES.md ./
COPY third_party ./third_party
RUN chmod -R a+rX,go-w /app \
    && python -m unittest discover -s tests -v \
    && groupadd --gid 10001 moonuestc \
    && useradd --uid 10001 --gid 10001 --no-create-home moonuestc \
    && mkdir /data \
    && chown 10001:10001 /data
ARG VCS_REF=unreleased
LABEL org.opencontainers.image.title="MoonUESTC Donson Portal" \
      org.opencontainers.image.version="0.5.1+donson.32" \
      org.opencontainers.image.source="https://github.com/DonsonHH/UESTC-MoonCheck" \
      org.opencontainers.image.revision="${VCS_REF}" \
      org.opencontainers.image.licenses="MIT"
USER 10001:10001
ENTRYPOINT ["python", "-m", "moonuestc"]
EXPOSE 8080
CMD ["serve"]
