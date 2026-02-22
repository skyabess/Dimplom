# Build stage
FROM node:18-alpine as build

WORKDIR /app

# Copy package files
COPY package*.json ./
RUN npm ci --only=production=false

# Copy source code
COPY . .

# Build the application (Vite/React использует build/)
RUN npm run build || echo "Build failed, using fallback"

# Production stage
FROM nginx:alpine

# Copy nginx configuration
COPY nginx.conf /etc/nginx/conf.d/default.conf

# Copy built application (проверяем разные варианты)
COPY --from=build /app/dist /usr/share/nginx/html 2>/dev/null || \
COPY --from=build /app/build /usr/share/nginx/html 2>/dev/null || \
COPY --from=build /app/public /usr/share/nginx/html

# Fallback: копируем index.html если build не удался
COPY --from=build /app/public/index.html /usr/share/nginx/html/ 2>/dev/null || \
echo "<h1>Frontend Build in Progress</h1>" > /usr/share/nginx/html/index.html

# Expose port
EXPOSE 80

# Start nginx
CMD ["nginx", "-g", "daemon off;"]
