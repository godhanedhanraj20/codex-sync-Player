FROM node:23-slim AS builder

WORKDIR /app
COPY . .

WORKDIR /app/res
RUN npm ci --omit=dev


FROM node:23-slim

WORKDIR /app

# Copy the entire root (needed for config.env, start.sh, cert, etc.)
COPY --from=builder /app /app

WORKDIR /app/res
CMD ["node", "server.js"]