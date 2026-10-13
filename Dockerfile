FROM node:20-alpine

ENV NODE_ENV=production
WORKDIR /app

COPY package.json package-lock.json ./
RUN npm ci --omit=dev && npm cache clean --force

COPY src ./src
COPY docs ./docs

# Carpeta de documentos con dueño no-root
RUN mkdir -p /data/documentos && chown -R node:node /data/documentos

# El proceso no corre como root (mínimo privilegio)
USER node

EXPOSE 4000
HEALTHCHECK --interval=15s --timeout=3s --retries=5 \
  CMD wget -qO- http://127.0.0.1:4000/api/salud || exit 1

CMD ["node", "src/server.js"]
