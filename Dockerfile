# -- Stage 1: Build React frontend ---------------------------------------------
FROM node:20-slim AS builder

WORKDIR /build

# Install Python (needed by some native npm dependencies at build time)
RUN apt-get update && apt-get install -y python3 python3-pip --no-install-recommends \
    && rm -rf /var/lib/apt/lists/*

# Copy dependency manifests first for layer caching
COPY package.json package-lock.json ./
RUN npm install --legacy-peer-deps

# Copy source and build
COPY . .
RUN npm run build

# -- Stage 2: Production image --------------------------------------------------
FROM node:20-slim

WORKDIR /app

# Install Python 3 + pip for the scanner engine
RUN apt-get update && apt-get install -y python3 python3-pip --no-install-recommends \
    && rm -rf /var/lib/apt/lists/*

# Install Python scanner dependencies
COPY webguard/requirements.txt ./webguard/requirements.txt
RUN pip3 install --no-cache-dir -r webguard/requirements.txt --break-system-packages

# Copy Node modules and built assets from builder stage
COPY --from=builder /build/node_modules ./node_modules
COPY --from=builder /build/dist ./dist

# Copy application source
COPY package.json package-lock.json tsconfig.json vite.config.ts server.ts ./
COPY webguard/ ./webguard/

# Create DB directory and set permissions
RUN mkdir -p ./webguard && chmod 755 ./webguard

ENV NODE_ENV=production
ENV PORT=3000

EXPOSE 3000

HEALTHCHECK --interval=30s --timeout=10s --start-period=10s --retries=3 \
    CMD node -e "require('http').get('http://localhost:3000/api/dashboard', r => process.exit(r.statusCode === 200 ? 0 : 1)).on('error', () => process.exit(1))"

CMD ["node", "--import", "tsx/esm", "server.ts"]
