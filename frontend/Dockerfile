# FortKnoxx frontend image.
# Build stage compiles the CRA/craco bundle; runtime stage serves it via nginx.

FROM node:20-alpine AS builder

WORKDIR /app
COPY package.json yarn.lock ./
RUN yarn install --frozen-lockfile --network-timeout 600000

COPY . .
ARG REACT_APP_BACKEND_URL=http://localhost:8000
ENV REACT_APP_BACKEND_URL=$REACT_APP_BACKEND_URL
RUN yarn build


FROM nginx:1.27-alpine AS runtime

COPY --from=builder /app/build /usr/share/nginx/html
COPY nginx.conf /etc/nginx/conf.d/default.conf

EXPOSE 3000
HEALTHCHECK --interval=30s --timeout=5s --retries=3 \
    CMD wget -qO- http://localhost:3000/ >/dev/null || exit 1
