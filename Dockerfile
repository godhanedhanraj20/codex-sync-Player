FROM node:23 AS builder

WORKDIR /app
COPY . .

# Run install with devDependencies so postinstall.js can use esbuild
WORKDIR /app/res
RUN npm install && npm prune --omit=dev


FROM node:23-slim

WORKDIR /app

# Copy the entire root (needed for config.env, start.sh, cert, etc.)
COPY --from=builder /app /app

WORKDIR /app/res
CMD ["node", "server.js"]