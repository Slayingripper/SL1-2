#!/bin/bash
# Build script for PV SCADA HMI Admin Dashboard

set -e

echo "🔨 Building PV SCADA HMI Admin Dashboard..."
echo ""

# Check if Node.js is installed
if ! command -v node &> /dev/null; then
    echo "❌ Error: Node.js is not installed"
    echo "Install Node.js from: https://nodejs.org/"
    exit 1
fi

echo "✓ Node.js version: $(node --version)"
echo "✓ npm version: $(npm --version)"
echo ""

# Navigate to admin dashboard directory
cd admin-dashboard

# Install dependencies
echo "📦 Installing dependencies..."
if [ ! -d "node_modules" ]; then
    npm install
else
    echo "✓ node_modules exists, skipping install"
fi

# Build production bundle
echo ""
echo "⚛️  Building React app..."
npm run build

# Check if build was successful
if [ -d "dist" ] && [ -f "dist/index.html" ]; then
    echo ""
    echo "✅ Build complete!"
    echo ""
    echo "Output:"
    ls -lh dist/
    echo ""
    echo "Dashboard will be served at http://172.20.0.65/admin"
    echo ""
    echo "To start the server:"
    echo "  docker compose up -d pv-controller"
    echo ""
else
    echo "❌ Build failed - dist directory not created"
    exit 1
fi
