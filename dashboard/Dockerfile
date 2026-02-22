# ============================================================
# BlockSafe Dashboard — Production Build (Nginx)
# ============================================================

# ── Stage 1: Build ──────────────────────────────────────────
FROM node:20-slim AS build-stage

WORKDIR /app

COPY dashboard/package*.json ./
RUN npm install

COPY dashboard/ .
ARG VITE_SUPABASE_URL
ARG VITE_SUPABASE_ANON_KEY
ENV VITE_SUPABASE_URL=$VITE_SUPABASE_URL
ENV VITE_SUPABASE_ANON_KEY=$VITE_SUPABASE_ANON_KEY
RUN npm run build

# ── Stage 2: Runtime ────────────────────────────────────────
FROM nginx:stable-alpine AS production-stage

COPY --from=build-stage /app/dist /usr/share/nginx/html

# Custom nginx config to handle SPA routing if necessary
# COPY dashboard/nginx.conf /etc/nginx/conf.d/default.conf

EXPOSE 80

CMD ["nginx", "-g", "daemon off;"]
