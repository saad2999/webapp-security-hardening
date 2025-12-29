FROM node:18-alpine

# Create app directory
WORKDIR /usr/src/app

# Install dependencies first (caching optimization)
COPY package*.json ./
RUN npm ci --only=production

# Copy application source
COPY . .

# Expose the port your app runs on (for documentation)
EXPOSE 8080

# Health check to verify app is running
HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
  CMD node -e "require('http').get('http://localhost:${PORT:-8080}/health', (r) => {if(r.statusCode!==200)throw new Error()})"

# Run the application
CMD ["node", "server.js"]

# Add startup script to ensure the app uses PORT env variable
USER node