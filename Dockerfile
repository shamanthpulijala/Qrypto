# ============================================================
# Qrypto — Multi-stage Dockerfile
# Stage 1: Frontend build (Vite + React)
# Stage 2: Backend (Express + Prisma)
# ============================================================

# ── Stage 1: Frontend Build ──────────────────────────────────
FROM node:20-alpine AS frontend-build

WORKDIR /app

# Copy root package files
COPY package.json package-lock.json ./

# Install root dependencies (frontend)
RUN npm ci --ignore-scripts

# Copy frontend source
COPY index.html vite.config.ts tsconfig.json tsconfig.app.json tsconfig.node.json ./
COPY src/ src/
COPY shared/ shared/
COPY public/ public/

# Build frontend
RUN npm run build

# ── Stage 2: Backend ─────────────────────────────────────────
FROM node:20-alpine AS backend

WORKDIR /app

# Install dumb-init for proper signal handling
RUN apk add --no-cache dumb-init

# Copy server package files
COPY server/package.json server/package-lock.json ./

# Install server dependencies
RUN npm ci --ignore-scripts

# Copy server source
COPY server/ server/

# Copy shared engine (needed by server worker)
COPY shared/ shared/

# Copy Prisma schema and generate client
COPY server/prisma/ prisma/
RUN npx prisma generate

# Copy frontend build output (for serving static files in production)
COPY --from=frontend-build /app/dist/ dist/

# Create non-root user
RUN addgroup -g 1001 -S qrypto && \
    adduser -S qrypto -u 1001 -G qrypto

# Create necessary directories
RUN mkdir -p /app/server/uploads /app/server/tmp && \
    chown -R qrypto:qrypto /app

USER qrypto

EXPOSE 3001

# Health check
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
  CMD wget --no-verbose --tries=1 --spider http://localhost:3001/health || exit 1

ENTRYPOINT ["dumb-init", "--"]
CMD ["node", "server/dist/src/index.js"]
