#!/bin/bash

# ============================================
# FortKnoxx - Server Shutdown Script
# ============================================
# Stops MongoDB, Backend, and Frontend servers
# ============================================

echo "============================================"
echo "🛑 FortKnoxx Server Shutdown"
echo "============================================"
echo ""

# Detect OS
if [[ "$OSTYPE" == "darwin"* ]]; then
    OS="mac"
elif [[ "$OSTYPE" == "linux-gnu"* ]]; then
    OS="linux"
else
    OS="unknown"
fi

# Function to check if port is in use
port_in_use() {
    lsof -i:$1 &> /dev/null
}

STOPPED_COUNT=0

# ============================================
# Stop Backend (Port 8000)
# ============================================
echo "🚀 Stopping Backend..."

if port_in_use 8000; then
    echo "  Killing processes on port 8000..."
    lsof -ti:8000 | xargs kill -9 2>/dev/null
    sleep 1

    if port_in_use 8000; then
        echo "  ⚠  Failed to stop backend"
    else
        echo "  ✓ Backend stopped"
        ((STOPPED_COUNT++))
    fi
else
    echo "  Backend not running"
fi

# Also check PID file
if [ -f ".server_pids" ]; then
    BACKEND_PID=$(grep "BACKEND_PID" .server_pids | cut -d'=' -f2)
    if [ -n "$BACKEND_PID" ]; then
        kill -9 $BACKEND_PID 2>/dev/null && echo "  ✓ Killed backend process (PID: $BACKEND_PID)"
    fi
fi

# Legacy PID file support
if [ -f "backend.pid" ]; then
    PID=$(cat backend.pid)
    kill -9 $PID 2>/dev/null && echo "  ✓ Killed backend (PID: $PID)"
    rm backend.pid
fi

echo ""

# ============================================
# Stop Frontend (Port 3000)
# ============================================
echo "💻 Stopping Frontend..."

if port_in_use 3000; then
    echo "  Killing processes on port 3000..."
    lsof -ti:3000 | xargs kill -9 2>/dev/null
    sleep 1

    if port_in_use 3000; then
        echo "  ⚠  Failed to stop frontend"
    else
        echo "  ✓ Frontend stopped"
        ((STOPPED_COUNT++))
    fi
else
    echo "  Frontend not running"
fi

# Also check PID file
if [ -f ".server_pids" ]; then
    FRONTEND_PID=$(grep "FRONTEND_PID" .server_pids | cut -d'=' -f2)
    if [ -n "$FRONTEND_PID" ]; then
        kill -9 $FRONTEND_PID 2>/dev/null && echo "  ✓ Killed frontend process (PID: $FRONTEND_PID)"
    fi
fi

# Legacy PID file support
if [ -f "frontend.pid" ]; then
    PID=$(cat frontend.pid)
    kill -9 $PID 2>/dev/null && echo "  ✓ Killed frontend (PID: $PID)"
    rm frontend.pid
fi

# Clean up PID file
rm -f .server_pids 2>/dev/null

echo ""

# ============================================
# Stop MongoDB (Optional)
# ============================================
echo "🗄️  MongoDB Status:"

if port_in_use 27017; then
    echo "  MongoDB is running on port 27017"
    echo ""
    read -p "  Do you want to stop MongoDB? (y/N): " -n 1 -r
    echo ""

    if [[ $REPLY =~ ^[Yy]$ ]]; then
        if [ "$OS" = "mac" ]; then
            echo "  Stopping MongoDB via brew services..."
            brew services stop mongodb-community 2>/dev/null || brew services stop mongodb-community@7.0 2>/dev/null
            sleep 1

            if port_in_use 27017; then
                echo "  ⚠  MongoDB still running (may need manual shutdown)"
            else
                echo "  ✓ MongoDB stopped"
                ((STOPPED_COUNT++))
            fi

        elif [ "$OS" = "linux" ]; then
            echo "  Stopping MongoDB via systemctl..."
            sudo systemctl stop mongod 2>/dev/null || sudo systemctl stop mongodb 2>/dev/null
            sleep 1

            if port_in_use 27017; then
                echo "  ⚠  MongoDB still running"
            else
                echo "  ✓ MongoDB stopped"
                ((STOPPED_COUNT++))
            fi
        else
            echo "  Please stop MongoDB manually"
        fi
    else
        echo "  MongoDB left running"
    fi
else
    echo "  MongoDB not running"
fi

echo ""

# ============================================
# Summary
# ============================================
echo "============================================"
echo "✅ Shutdown Complete"
echo "============================================"
echo ""
echo "📊 Summary:"
echo "   • $STOPPED_COUNT service(s) stopped"
echo ""

if [ $STOPPED_COUNT -gt 0 ]; then
    echo "💡 To start servers again:"
    echo "   ./start_servers.sh"
else
    echo "💡 No servers were running"
fi

echo ""

exit 0
