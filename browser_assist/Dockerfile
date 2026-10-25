ARG MOON_APP_IMAGE=moonuestc-local:student-portal
FROM ${MOON_APP_IMAGE}
USER root
RUN apt-get update && apt-get install -y --no-install-recommends chromium fonts-noto-cjk \
    && rm -rf /var/lib/apt/lists/* \
    && python -m pip install --no-cache-dir playwright==1.58.0
COPY service.py /browser/service.py
COPY page_snapshot.js page_assets.py access_policy.py auth_status.js /browser/
USER 10001:10001
ENTRYPOINT ["python","/browser/service.py"]
