#!/bin/bash

# Function to check if a command exists
command_exists() {
    command -v "$1" >/dev/null 2>&1
}

# Check for MongoDB
if ! pgrep -x "mongod" > /dev/null; then
    echo "MongoDB is not running. Attempting to start..."
    if command_exists brew; then
        echo "Trying via brew services..."
        brew services start mongodb-community
    else
        echo "Trying direct mongod start..."
        mkdir -p /tmp/mongodb_data
        mongod --fork --logpath /tmp/mongod.log --dbpath /tmp/mongodb_data
    fi
    
    # Give it a moment to start
    sleep 2
    
    if ! pgrep -x "mongod" > /dev/null; then
        echo "WARNING: Failed to start MongoDB. Please start it manually."
    else
        echo "MongoDB started."
    fi
else
    echo "MongoDB is already running."
fi

# Backend
echo "-----------------------------------"
echo "Setting up Backend..."
cd backend
if [ ! -d "venv" ]; then
    echo "Creating virtual environment with Python 3.10..."
    python3.10 -m venv venv
fi
source venv/bin/activate
echo "Python version: $(python --version)"
echo "Installing requirements..."
pip install -r requirements.txt

echo "Starting Backend Server..."
# Run in background, save PID
uvicorn server:app --reload --port 8000 > ../backend.log 2>&1 &
BACKEND_PID=$!
echo $BACKEND_PID > ../backend.pid
echo "Backend running on port 8000 (PID: $BACKEND_PID)"
cd ..

# Frontend
echo "-----------------------------------"
echo "Setting up Frontend..."
cd frontend

echo "Cleaning cache and build artifacts..."
# Remove build directory if it exists
if [ -d "build" ]; then
    echo "Removing old build directory..."
    rm -rf build
fi

# Clear node cache
if [ -d "node_modules/.cache" ]; then
    echo "Clearing node_modules cache..."
    rm -rf node_modules/.cache
fi

echo "Installing dependencies..."
yarn install

echo "Starting Frontend Server (with fresh cache)..."
# Run in background, save PID
# BROWSER=none prevents opening a browser window automatically
BROWSER=none yarn start > ../frontend.log 2>&1 &
FRONTEND_PID=$!
echo $FRONTEND_PID > ../frontend.pid
echo "Frontend running on port 3000 (PID: $FRONTEND_PID)"
cd ..

echo "-----------------------------------"
echo "Servers are up and running!"
echo "Backend logs: backend.log"
echo "Frontend logs: frontend.log"
echo "To stop servers, run: ./stop_servers.sh"
echo ""
echo "⚠️  IMPORTANT: If you see cached content (old branding/badges):"
echo "   - Press Ctrl+Shift+R (or Cmd+Shift+R on Mac) for hard refresh"
echo "   - Or clear browser cache and reload"
