FROM node:20-slim

# Install Chromium for puppeteer
RUN apt-get update && apt-get install -y --no-install-recommends \
  chromium \
  ca-certificates \
  libgtk-3-0 \
  libgbm-dev \
  libasound2 \
  && rm -rf /var/lib/apt/lists/*

WORKDIR /home/victim
RUN npm init -y && npm install puppeteer node-fetch@2 --no-audit --no-fund
COPY victim_runner.js ./
COPY victim_cyber_range.js ./

CMD ["node","victim_runner.js"]
