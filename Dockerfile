FROM node:18-alpine

# Set environment to production
ENV NODE_ENV=production

# Create app directory and set permissions
WORKDIR /usr/src/app

# Copy manifests first
COPY package*.json ./

# Install production dependencies
RUN npm ci --only=production

# Copy application source
COPY . .

# Ensure the 'node' user owns the files
RUN chown -R node:node /usr/src/app

# Cloud Run uses the PORT env var (usually 8080)
EXPOSE 8080

# Switch to non-root user for security
USER node

# Start the application
# We use 'node server.js' directly to ensure signals (SIGTERM) are handled correctly
CMD ["node", "server.js"]