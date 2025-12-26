FROM node:18-alpine

# Create app directory
WORKDIR /app

# Install app dependencies (production)
COPY package*.json ./
RUN npm ci --only=production

# Copy app source
COPY . .

# Ensure non-root user for security
RUN chown -R node:node /app
USER node

ENV PORT=8080
EXPOSE 8080

# Start the server
CMD ["node", "server.js"]
