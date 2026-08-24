# TikTok Signature Server
FROM node:20-slim

# Install Chromium and dependencies
#
# `ca-certificates` is NOT bundled by `node:20-slim` — without it, neither `curl` nor
# the Debian-packaged `chromium` below (which validates TLS through NSS + the system
# trust store, unlike Google's own Chrome builds and unlike Node's own `fetch`, which
# both carry their own root store) has any CA to verify against. Every HTTPS request
# the in-page browser makes — including the ones the TikTok SDK triggers on its own —
# failed with a bare "Failed to fetch" and no other clue, until this was added.
RUN apt-get update && apt-get install -y \
    ca-certificates \
    chromium \
    fonts-liberation \
    libasound2 \
    libatk-bridge2.0-0 \
    libatk1.0-0 \
    libcups2 \
    libdbus-1-3 \
    libdrm2 \
    libgbm1 \
    libgtk-3-0 \
    libnspr4 \
    libnss3 \
    libx11-xcb1 \
    libxcomposite1 \
    libxdamage1 \
    libxrandr2 \
    xdg-utils \
    curl \
    --no-install-recommends \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Copy package files
COPY package*.json ./

# Install dependencies (production only)
RUN npm ci --only=production

# Copy application files
COPY server.mjs ./
COPY xgnarly.mjs ./
COPY benchmark.mjs ./
COPY javascript/ ./javascript/
# StreamPack addition: the custom sign-server routes (see routes/webcast-connect.mjs).
COPY routes/ ./routes/

# Set Chrome path for Puppeteer
ENV PUPPETEER_EXECUTABLE_PATH=/usr/bin/chromium
ENV PUPPETEER_SKIP_CHROMIUM_DOWNLOAD=true
ENV PORT=8080

EXPOSE 8080

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=60s --retries=3 \
    CMD curl -f http://localhost:8080/health || exit 1

CMD ["node", "server.mjs"]
