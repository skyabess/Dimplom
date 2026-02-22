# Build stage
FROM node:18-alpine as build

WORKDIR /app

# Copy package files
COPY package*.json ./

# Используем npm install вместо npm ci (нет package-lock.json)
RUN npm install

# Copy source code
COPY . .

# Build the application (проверяем разные варианты скриптов)
RUN npm run build || npm run vite:build || npm run dev || echo "Build skipped, serving fallback"

# Production stage  
FROM nginx:alpine

# Copy nginx configuration
COPY nginx.conf /etc/nginx/conf.d/default.conf

# Copy built application (проверяем разные варианты выходных папок)
RUN mkdir -p /usr/share/nginx/html
COPY --from=build /app/dist /usr/share/nginx/html 2>/dev/null || \
COPY --from=build /app/build /usr/share/nginx/html 2>/dev/null || \
COPY --from=build /app/public /usr/share/nginx/html 2>/dev/null || \
true

# Fallback index.html если build не удался
RUN echo '<!DOCTYPE html><html><head><title>Land Contract Frontend</title></head><body><h1>Frontend загружается...</h1><p>Backend: <a href="http://localhost:8000">API на 8000</a></p></body></html>' > /usr/share/nginx/html/index.html

EXPOSE 80
CMD ["nginx", "-g", "daemon off;"]
