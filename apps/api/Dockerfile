FROM node:20-alpine
WORKDIR /app
COPY apps/api/package*.json ./
RUN npm ci --omit=dev || npm install --omit=dev
COPY apps/api .
EXPOSE 8080
CMD ["node", "server.js"]
