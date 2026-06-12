FROM node:24-alpine AS builder
WORKDIR /app
ARG VITE_CEEM_API_URL=http://localhost:8080
ENV VITE_CEEM_API_URL=$VITE_CEEM_API_URL
COPY web/package*.json ./
RUN npm ci
COPY web ./
RUN npm run build

FROM nginx:1.29-alpine AS runtime
COPY web/nginx.conf /etc/nginx/conf.d/default.conf
COPY --from=builder /app/dist /usr/share/nginx/html
EXPOSE 80
CMD ["nginx", "-g", "daemon off;"]
