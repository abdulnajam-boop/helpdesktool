FROM node:22-alpine AS build
WORKDIR /app
COPY package*.json ./
RUN npm install
COPY . .
ARG VITE_API_URL=http://localhost:8000
ENV VITE_API_URL=$VITE_API_URL
# All optional -- unset by default, which keeps the development login page
# active (see helpdesktool CLAUDE.md's auth trust model). Set every one of
# VITE_OIDC_ISSUER/VITE_OIDC_CLIENT_ID to switch the login page to a real
# OIDC provider via the Authorization Code + PKCE flow (frontend/src/auth/oidc.ts).
ARG VITE_OIDC_ISSUER=""
ARG VITE_OIDC_CLIENT_ID=""
ARG VITE_OIDC_AUDIENCE=""
ARG VITE_OIDC_REDIRECT_URI=""
ARG VITE_OIDC_SCOPE=""
ENV VITE_OIDC_ISSUER=$VITE_OIDC_ISSUER
ENV VITE_OIDC_CLIENT_ID=$VITE_OIDC_CLIENT_ID
ENV VITE_OIDC_AUDIENCE=$VITE_OIDC_AUDIENCE
ENV VITE_OIDC_REDIRECT_URI=$VITE_OIDC_REDIRECT_URI
ENV VITE_OIDC_SCOPE=$VITE_OIDC_SCOPE
RUN npm run build
FROM nginx:1.31-alpine
# Picks up any Alpine security patches released after this base image tag
# was built, without waiting on a new nginx image tag -- keeps the image
# self-healing on every rebuild rather than only when we remember to bump
# the pinned tag above.
RUN apk update && apk upgrade --no-cache
COPY nginx.conf /etc/nginx/conf.d/default.conf
COPY --from=build /app/dist /usr/share/nginx/html
EXPOSE 80
