FROM node:20-alpine
WORKDIR /app
COPY apps/web/package*.json ./
RUN npm ci --omit=dev || npm install --omit=dev
COPY apps/web .
EXPOSE 8080
CMD ["node", "server.js"]
