FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    DAFIT_DATA_DIR=/data \
    DAFIT_HOST=0.0.0.0 \
    DAFIT_PORT=8080

WORKDIR /app

COPY app.py ./

RUN addgroup --system dafit && adduser --system --ingroup dafit dafit \
    && mkdir -p /data/uploads /data/db \
    && chown -R dafit:dafit /app /data

USER dafit

EXPOSE 8080
VOLUME ["/data"]

CMD ["python", "app.py"]
