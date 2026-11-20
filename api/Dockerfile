# ─── Build stage ──────────────────────────────────────────────────────────────
FROM node:22-alpine AS build

WORKDIR /app

COPY package.json package-lock.json* ./
RUN npm ci --ignore-scripts

COPY prisma ./prisma
COPY src ./src
COPY tsconfig.json ./

RUN npm run build
RUN npx prisma generate

# ─── Dev stage ────────────────────────────────────────────────────────────────
FROM node:22-alpine AS dev

WORKDIR /app
COPY package.json package-lock.json* ./
RUN npm ci --ignore-scripts
COPY prisma ./prisma
COPY src ./src
COPY tsconfig.json ./
RUN npx prisma generate
CMD ["npm", "run", "dev"]

# ─── Production stage ─────────────────────────────────────────────────────────
FROM node:22-alpine AS production

ENV NODE_ENV=production
WORKDIR /app

COPY package.json package-lock.json* ./
RUN npm ci --omit=dev --ignore-scripts

COPY --from=build /app/dist ./dist
COPY --from=build /app/generated ./generated
COPY prisma ./prisma

# Run migrations then start
CMD ["sh", "-c", "npx prisma migrate deploy && node dist/src/server.js"]
