# Production Container for VeriChain Enterprise
FROM node:20-alpine

# Set working directory
WORKDIR /usr/src/app

# Install dependencies
COPY package*.json ./
RUN npm ci --only=production

# Bundle app source
COPY . .

# Ensure data directories exist with proper permissions
RUN mkdir -p vault_storage test_samples

# Expose server port
EXPOSE 3000

# Set environment
ENV NODE_ENV=production
ENV PORT=3000

# Start server
CMD ["node", "server.js"]
