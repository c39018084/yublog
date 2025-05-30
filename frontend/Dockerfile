# Development Dockerfile for React frontend
FROM node:20-alpine

# Install curl for health checks
RUN apk add --no-cache curl

# Set working directory
WORKDIR /app

# Copy package files first for better caching
COPY package*.json ./

# Install dependencies
RUN npm ci

# Copy public assets (changes less frequently than src)
COPY public/ ./public/

# Copy configuration files
COPY tailwind.config.js postcss.config.js ./

# Build arguments
ARG REACT_APP_API_URL
ARG REACT_APP_WEBAUTHN_RP_ID

# Set environment variables
ENV REACT_APP_API_URL=$REACT_APP_API_URL
ENV REACT_APP_WEBAUTHN_RP_ID=$REACT_APP_WEBAUTHN_RP_ID

# Disable WebSocket connections to prevent console errors in proxy setup
ENV FAST_REFRESH=false
ENV CHOKIDAR_USEPOLLING=true
ENV GENERATE_SOURCEMAP=false

# Copy source code last (changes most frequently)
COPY src/ ./src/

# Expose port
EXPOSE 3000

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD curl -f http://localhost:3000 || exit 1

# Start development server
CMD ["npm", "start"] 