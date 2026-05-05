#!/bin/bash

# ============================================
# FortKnoxx - Unified Server Startup Script
# ============================================
# Starts MongoDB, Backend (FastAPI), and Frontend (React)
# ============================================

set -e

echo "============================================"
echo "🔒 FortKnoxx Server Startup"
echo "============================================"
echo ""

# Detect OS
if [[ "$OSTYPE" == "darwin"* ]]; then
    OS="mac"
elif [[ "$OSTYPE" == "linux-gnu"* ]]; then
    OS="linux"
else
    echo "❌ Unsupported OS: $OSTYPE"
    exit 1
fi

# Function to check if command exists
command_exists() {
    command -v "$1" &> /dev/null
}

# Function to check if port is in use
port_in_use() {
    lsof -i:$1 &> /dev/null
}

# ============================================
# STEP 1: Check Prerequisites
# ============================================
echo "📋 Step 1: Checking prerequisites..."
echo ""

MISSING_DEPS=0

# Check Python — require 3.10+ (3.9 is EOL and breaks scipy/sklearn/numpy)
PYTHON_BIN=""
for candidate in python3.12 python3.11 python3.10; do
    if command_exists "$candidate"; then
        PYTHON_BIN="$candidate"
        break
    fi
done

if [ -n "$PYTHON_BIN" ]; then
    PYTHON_VERSION=$($PYTHON_BIN --version 2>&1 | awk '{print $2}')
    echo "  ✓ Python $PYTHON_VERSION found ($PYTHON_BIN)"
elif command_exists python3; then
    PYTHON_VERSION=$(python3 --version 2>&1 | awk '{print $2}')
    PY_MAJOR=$(echo "$PYTHON_VERSION" | cut -d. -f1)
    PY_MINOR=$(echo "$PYTHON_VERSION" | cut -d. -f2)
    if [ "$PY_MAJOR" -eq 3 ] && [ "$PY_MINOR" -ge 10 ]; then
        PYTHON_BIN="python3"
        echo "  ✓ Python $PYTHON_VERSION found"
    else
        echo "  ❌ Python $PYTHON_VERSION is too old. Python 3.10+ required."
        echo "     macOS: brew install python@3.11"
        echo "     Linux: use deadsnakes PPA or pyenv"
        MISSING_DEPS=1
    fi
else
    echo "  ❌ Python 3 not found. Please install Python 3.10+"
    MISSING_DEPS=1
fi

# Check MongoDB
if command_exists mongod; then
    echo "  ✓ MongoDB found"
else
    echo "  ❌ MongoDB not found"
    echo "     macOS: brew install mongodb-community"
    echo "     Linux: https://docs.mongodb.com/manual/installation/"
    MISSING_DEPS=1
fi

# Check Node.js
if command_exists node; then
    NODE_VERSION=$(node --version)
    echo "  ✓ Node.js $NODE_VERSION found"
else
    echo "  ❌ Node.js not found. Please install Node.js 16+"
    MISSING_DEPS=1
fi

# Check Yarn
if command_exists yarn; then
    YARN_VERSION=$(yarn --version)
    echo "  ✓ Yarn $YARN_VERSION found"
else
    echo "  ⚠  Yarn not found. Installing..."
    npm install -g yarn 2>/dev/null || echo "  ❌ Failed to install Yarn"
fi

if [ $MISSING_DEPS -eq 1 ]; then
    echo ""
    echo "❌ Missing dependencies. Run: ./install_all_scanners.sh"
    exit 1
fi

echo ""

# ============================================
# STEP 2: Check Configuration
# ============================================
echo "⚙️  Step 2: Checking configuration..."
echo ""

if [ ! -f "backend/.env" ]; then
    echo "  ⚠  backend/.env not found"

    if [ -f "backend/.env.sample" ]; then
        cp backend/.env.sample backend/.env
        echo "  ✓ Created backend/.env from sample"
        echo ""
        echo "  ⚠  IMPORTANT: Configure backend/.env with:"
        echo "     1. JWT_SECRET_KEY (generate: openssl rand -hex 32)"
        echo "     2. ENCRYPTION_MASTER_KEY (generate: python3 -c \"from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())\")"
        echo ""
        read -p "  Press Enter after configuring .env, or Ctrl+C to exit..."
    else
        echo "  ❌ backend/.env.sample not found"
        exit 1
    fi
else
    echo "  ✓ backend/.env exists"

    # Check if keys are configured
    if grep -q "CHANGE-THIS" backend/.env 2>/dev/null; then
        echo "  ⚠  WARNING: Default keys detected in .env"
        echo "     Please generate secure keys for production"
    fi
fi

echo ""

# ============================================
# STEP 3: Start MongoDB
# ============================================
echo "🗄️  Step 3: Starting MongoDB..."
echo ""

if port_in_use 27017; then
    echo "  ✓ MongoDB already running on port 27017"
else
    echo "  Starting MongoDB..."

    if [ "$OS" = "mac" ]; then
        brew services start mongodb-community 2>/dev/null || brew services start mongodb-community@7.0 2>/dev/null
        sleep 2

        if port_in_use 27017; then
            echo "  ✓ MongoDB started"
        else
            echo "  ❌ Failed to start MongoDB"
            echo "     Try: mongod --config /usr/local/etc/mongod.conf"
            exit 1
        fi

    elif [ "$OS" = "linux" ]; then
        if command_exists systemctl; then
            sudo systemctl start mongod 2>/dev/null || sudo systemctl start mongodb 2>/dev/null
            sleep 2

            if port_in_use 27017; then
                echo "  ✓ MongoDB started"
            else
                echo "  ❌ Failed to start MongoDB"
                exit 1
            fi
        fi
    fi
fi

echo ""

# ============================================
# STEP 4: Start Backend
# ============================================
echo "🚀 Step 4: Starting Backend (FastAPI)..."
echo ""

# Kill existing backend if running
if port_in_use 8000; then
    echo "  ⚠  Port 8000 in use. Stopping existing process..."
    lsof -ti:8000 | xargs kill -9 2>/dev/null || true
    sleep 1
fi

# Validate existing venv was built with Python 3.10+ — recreate if not
if [ -d "backend/venv" ]; then
    VENV_PY_VER=""
    if [ -x "backend/venv/bin/python" ]; then
        VENV_PY_VER=$(backend/venv/bin/python -c 'import sys; print("{}.{}".format(sys.version_info[0], sys.version_info[1]))' 2>/dev/null || echo "")
    fi

    NEEDS_RECREATE=0
    if [ -z "$VENV_PY_VER" ]; then
        echo "  ⚠  Existing venv interpreter is broken or missing. Recreating..."
        NEEDS_RECREATE=1
    else
        VENV_MAJOR=$(echo "$VENV_PY_VER" | cut -d. -f1)
        VENV_MINOR=$(echo "$VENV_PY_VER" | cut -d. -f2)
        if [ "$VENV_MAJOR" != "3" ] || [ "$VENV_MINOR" -lt 10 ]; then
            echo "  ⚠  Existing venv uses Python $VENV_PY_VER (need 3.10+). Recreating..."
            NEEDS_RECREATE=1
        fi
    fi

    if [ "$NEEDS_RECREATE" = "1" ]; then
        rm -rf backend/venv
    fi
fi

# Setup virtual environment
if [ ! -d "backend/venv" ]; then
    echo "  Creating Python virtual environment with $PYTHON_BIN..."
    cd backend
    $PYTHON_BIN -m venv venv
    cd ..
    echo "  ✓ Virtual environment created"
fi

# Install dependencies if needed
if [ ! -f "backend/venv/bin/uvicorn" ]; then
    echo "  Installing Python dependencies (this may take 2-3 minutes)..."
    cd backend
    source venv/bin/activate
    pip install -q --upgrade pip wheel "setuptools<82"
    # Pin numpy<2 first — scipy/sklearn wheels are built against NumPy 1.x and
    # crash with "_ARRAY_API not found" on NumPy 2.x.
    pip install -q "numpy<2"
    # Use constraints.txt to resolve known conflicts between checkov, torch,
    # transformers, safety, and huggingface deps. Falls back gracefully if
    # the file is missing (e.g. fresh clone without constraints.txt).
    if [ -f "constraints.txt" ]; then
        CONSTRAINTS_FLAG="-c constraints.txt"
    else
        echo "  ⚠  constraints.txt not found — installing without version constraints"
        CONSTRAINTS_FLAG=""
    fi
    if ! pip install -q -r requirements.txt $CONSTRAINTS_FLAG; then
        echo "  ⚠  Strict resolver failed. Retrying with legacy resolver..."
        pip install -r requirements.txt $CONSTRAINTS_FLAG --use-deprecated=legacy-resolver
    fi
    cd ..
    echo "  ✓ Dependencies installed"
fi

# Start backend
echo "  Starting backend server..."
cd backend
source venv/bin/activate
nohup uvicorn server:app --host 0.0.0.0 --port 8000 > backend.log 2>&1 &
BACKEND_PID=$!
cd ..

# Wait for backend to start (ML models take ~5-10 seconds to load)
echo "  Waiting for backend to initialize (loading ML models)..."
for i in {1..15}; do
    if port_in_use 8000; then
        # Give it one more second to ensure it's stable
        sleep 1
        break
    fi
    sleep 1
    [ $((i % 3)) -eq 0 ] && echo -n "."
done
echo ""

if port_in_use 8000; then
    echo "  ✓ Backend started (PID: $BACKEND_PID)"
    echo "     API: http://localhost:8000"
    echo "     Docs: http://localhost:8000/docs"
else
    echo "  ❌ Failed to start backend"
    echo "     Check: tail -f backend/backend.log"
    exit 1
fi

echo ""

# ============================================
# STEP 5: Start Frontend
# ============================================
echo "💻 Step 5: Starting Frontend (React)..."
echo ""

# Kill existing frontend if running
if port_in_use 3000; then
    echo "  ⚠  Port 3000 in use. Stopping existing process..."
    lsof -ti:3000 | xargs kill -9 2>/dev/null || true
    sleep 1
fi

# Install frontend dependencies if needed
if [ ! -d "frontend/node_modules" ]; then
    echo "  Installing frontend dependencies (this may take 3-5 minutes)..."
    cd frontend
    yarn install
    cd ..
    echo "  ✓ Dependencies installed"
fi

# Clear cache for clean start
if [ -d "frontend/node_modules/.cache" ]; then
    echo "  Clearing frontend cache..."
    rm -rf frontend/node_modules/.cache
fi

# Start frontend
echo "  Starting frontend server..."
cd frontend
export REACT_APP_BACKEND_URL=http://localhost:8000
BROWSER=none nohup yarn start > frontend.log 2>&1 &
FRONTEND_PID=$!
cd ..

# Wait for frontend to start
echo "  Waiting for frontend..."
for i in {1..30}; do
    if port_in_use 3000; then
        break
    fi
    sleep 1
    [ $((i % 5)) -eq 0 ] && echo -n "."
done
echo ""

if port_in_use 3000; then
    echo "  ✓ Frontend started (PID: $FRONTEND_PID)"
    echo "     URL: http://localhost:3000"
else
    echo "  ❌ Failed to start frontend"
    echo "     Check: tail -f frontend/frontend.log"
    exit 1
fi

echo ""

# ============================================
# SUCCESS!
# ============================================
echo "============================================"
echo "✅ All servers started successfully!"
echo "============================================"
echo ""
echo "📍 Services:"
echo "   • MongoDB:  mongodb://localhost:27017"
echo "   • Backend:  http://localhost:8000 (PID: $BACKEND_PID)"
echo "   • Frontend: http://localhost:3000 (PID: $FRONTEND_PID)"
echo ""
echo "📚 Documentation:"
echo "   • Swagger UI: http://localhost:8000/docs"
echo "   • ReDoc:      http://localhost:8000/redoc"
echo ""
echo "📝 Logs:"
echo "   • Backend:  tail -f backend/backend.log"
echo "   • Frontend: tail -f frontend/frontend.log"
echo ""
echo "🛑 To stop all servers:"
echo "   ./stop_servers.sh"
echo ""
echo "🌐 Open your browser:"
echo "   http://localhost:3000"
echo ""
echo "💡 Tip: Press Ctrl+Shift+R for hard refresh if you see cached content"
echo ""
echo "Happy scanning! 🔒"
echo ""

# Save PIDs for stop script
echo "BACKEND_PID=$BACKEND_PID" > .server_pids
echo "FRONTEND_PID=$FRONTEND_PID" >> .server_pids

exit 0
