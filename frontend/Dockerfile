FROM node:20-slim

WORKDIR /app

# Install dependencies first (better caching)
COPY package.json package-lock.json* ./
RUN npm install

# Copy application code
COPY . .

# Set environment
ENV NODE_ENV=development
ENV NEXT_TELEMETRY_DISABLED=1
ENV HOSTNAME=0.0.0.0

EXPOSE 3000

# Run in development mode - bind to all interfaces
CMD ["npm", "run", "dev", "--", "-H", "0.0.0.0"]
