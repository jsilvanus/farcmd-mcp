# syntax=docker/dockerfile:1
# farcmd-mcp production image. Data (SQLite) lives in the /data volume; secrets come from the environment.

FROM node:22-bookworm-slim AS build
WORKDIR /app
COPY package.json package-lock.json ./
RUN npm ci
COPY tsconfig.json vite.config.ts ./
COPY src ./src
COPY web ./web
RUN npm run build && npm prune --omit=dev

FROM node:22-bookworm-slim
ENV NODE_ENV=production \
    HOST=0.0.0.0 \
    PORT=5999 \
    STORAGE_PATH=/data/app.sqlite \
    NODE_OPTIONS=--disable-warning=ExperimentalWarning
WORKDIR /app
COPY --from=build /app/package.json ./
COPY --from=build /app/node_modules ./node_modules
COPY --from=build /app/dist ./dist
# farcmd-admin on PATH: docker compose exec farcmd farcmd-admin user list
RUN printf '#!/bin/sh\nexec node /app/dist/cli/admin.js "$@"\n' > /usr/local/bin/farcmd-admin \
 && chmod 0755 /usr/local/bin/farcmd-admin \
 && mkdir -p /data && chown node:node /data
USER node
VOLUME ["/data"]
EXPOSE 5999
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
  CMD node -e "fetch('http://127.0.0.1:'+(process.env.PORT||5999)+'/health').then(r=>process.exit(r.ok?0:1),()=>process.exit(1))"
CMD ["node", "dist/server.js"]
