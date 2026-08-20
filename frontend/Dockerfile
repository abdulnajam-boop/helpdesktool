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
# Re-declared here (ARGs don't cross the FROM boundary from the build stage
# above) purely to compute the CSP's connect-src: the bundle in dist/ is
# static JS that can only ever call the API origin and (if configured) the
# OIDC issuer origin it was built against, so the policy is baked in at
# image build time rather than left wide open.
ARG VITE_API_URL=http://localhost:8000
ARG VITE_OIDC_ISSUER=""
COPY nginx.conf /etc/nginx/conf.d/default.conf
RUN CONNECT_SRC="'self' ${VITE_API_URL}"; \
    if [ -n "${VITE_OIDC_ISSUER}" ]; then CONNECT_SRC="${CONNECT_SRC} ${VITE_OIDC_ISSUER}"; fi; \
    sed -i "s#__CSP_CONNECT_SRC__#${CONNECT_SRC}#" /etc/nginx/conf.d/default.conf
COPY --from=build /app/dist /usr/share/nginx/html
EXPOSE 80
