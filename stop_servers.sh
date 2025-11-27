#!/bin/bash

echo "Stopping servers..."

# Stop Backend
if [ -f backend.pid ]; then
    PID=$(cat backend.pid)
    if ps -p $PID > /dev/null; then
        echo "Stopping Backend (PID: $PID)..."
        kill $PID
    else
        echo "Backend process $PID not found."
    fi
    rm backend.pid
else
    echo "backend.pid not found. Checking for uvicorn process..."
    PIDS=$(pgrep -f "uvicorn server:app")
    if [ -n "$PIDS" ]; then
        echo "Found uvicorn processes: $PIDS. Killing..."
        kill $PIDS
    else
        echo "No backend process found."
    fi
fi

# Stop Frontend
if [ -f frontend.pid ]; then
    PID=$(cat frontend.pid)
    if ps -p $PID > /dev/null; then
        echo "Stopping Frontend (PID: $PID)..."
        kill $PID
    else
        echo "Frontend process $PID not found."
    fi
    rm frontend.pid
else
    echo "frontend.pid not found."
fi

echo "Done."
