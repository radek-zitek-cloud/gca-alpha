#!/bin/bash

# API Gateway Startup Script

echo "🚀 Starting API Gateway..."

# Check if virtual environment is activated
if [[ "$VIRTUAL_ENV" != "" ]]; then
    echo "✅ Virtual environment is active: $VIRTUAL_ENV"
else
    echo "⚠️  Virtual environment not detected. Activating..."
    source .venv/bin/activate
fi

# Install dependencies if needed
echo "📦 Installing dependencies..."
pip install -r requirements/base.txt > /dev/null 2>&1

# Start the server
echo "🌐 Starting FastAPI server on http://localhost:8000"
echo "📚 API Documentation available at http://localhost:8000/docs"
echo "📊 Health Check: http://localhost:8000/api/v1/health"
echo "🔧 Gateway Services: http://localhost:8000/gateway/services"
echo ""
echo "Press Ctrl+C to stop the server"
echo ""

uvicorn app.main:app --host 0.0.0.0 --port 8000 --reload
