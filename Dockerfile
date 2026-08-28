FROM node:20-alpine
WORKDIR /app
COPY server/package.json server/package-lock.json ./
RUN npm ci --omit=dev
COPY server/index.mjs server/auth.mjs server/redis.mjs server/acl-check.mjs server/audit-db.mjs ./
COPY server/bridges/ ./bridges/
RUN adduser -D appuser \
    && chown -R appuser /app \
    && mkdir -p /etc/suitecrm-mcp \
    && chown appuser /etc/suitecrm-mcp
USER appuser
EXPOSE 3100
EXPOSE 3101
# Metrics ports are bound to 127.0.0.1 by default. Set METRICS_BIND=0.0.0.0 so
# a Prometheus container on the same Docker network can reach them by service name.
EXPOSE 9090
EXPOSE 9091
# Healthcheck defined per-service in docker-compose (auth=3100, gateway=3101).
# No default here - hardcoding either port would be wrong for the other service.
CMD ["node", "index.mjs"]
