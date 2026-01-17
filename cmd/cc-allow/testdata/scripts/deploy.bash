#!/bin/bash
# Example deployment script

set -euo pipefail

echo "Starting deployment..."

# Build the project
npm run build

# Run tests
npm test

# Deploy to production
rsync -avz ./dist/ server:/var/www/app/

echo "Deployment complete!"
