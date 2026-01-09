FROM python:3.11-slim

ARG APP_DIR=/opt/pv-controller
WORKDIR $APP_DIR

RUN apt-get update && apt-get install -y --no-install-recommends \
    netcat-openbsd \
    tcpdump \
    ca-certificates \
    curl \
    && rm -rf /var/lib/apt/lists/*

RUN mkdir -p /opt/pv-controller/logs

RUN pip install --no-cache-dir flask flask-cors paho-mqtt pymodbus

COPY server.py $APP_DIR/
COPY server_cyber_range.py $APP_DIR/
COPY static/ $APP_DIR/static/
COPY scripts/ $APP_DIR/scripts/
COPY admin-dashboard/dist/ $APP_DIR/admin-dashboard/dist/

EXPOSE 80 15002

CMD ["python3", "server_cyber_range.py"]
