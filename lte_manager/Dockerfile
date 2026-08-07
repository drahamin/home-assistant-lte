FROM python:3.12-alpine3.20

ARG BUILD_VERSION
ARG BUILD_ARCH
LABEL io.hass.version="${BUILD_VERSION}" \
      io.hass.type="app" \
      io.hass.arch="${BUILD_ARCH}" \
      org.opencontainers.image.title="Baiamonte LTE" \
      org.opencontainers.image.source="https://github.com/drahamin/home-assistant-lte"

RUN apk add --no-cache bash ccid iputils pcsc-lite-libs pcsc-lite \
      pcsc-lite-dev gcc musl-dev swig \
    && pip install --no-cache-dir pyscard==2.3.1 \
    && apk del pcsc-lite-dev gcc musl-dev swig
WORKDIR /app
COPY requirements.txt /app/requirements.txt
RUN pip install --no-cache-dir -r /app/requirements.txt
COPY app /app
COPY run.sh /run.sh
RUN chmod 0755 /run.sh
RUN mkdir -p /data /config
ENV BIND_HOST=0.0.0.0 PORT=8099 PYTHONUNBUFFERED=1
EXPOSE 8099
CMD ["/run.sh"]
