FROM node:20-alpine
WORKDIR /app

COPY package.json package-lock.json ./
RUN npm ci --omit=dev

COPY . .

# Entry point is overridden per-service via `command` in docker-compose / k8s
CMD ["node", "demo/server.js"]
