FROM node:20-alpine
WORKDIR /app
COPY apps/worker/package*.json ./
RUN npm ci --omit=dev || npm install --omit=dev
COPY apps/worker .
CMD ["node", "src/index.js"]
