#!/usr/bin/env bash
set -e

ROOT="$(cd "$(dirname "$0")" && pwd)"

# Backend
cd "$ROOT/backend"
if [ ! -d venv ]; then
  python3.11 -m venv venv
  source venv/bin/activate
  pip install -r requirements.txt
else
  source venv/bin/activate
fi

export DATABASE_URL="${DATABASE_URL:-sqlite:///$ROOT/backend/identitylens.db}"
echo "Starting backend on http://localhost:8000 (DB: $DATABASE_URL)"
uvicorn app.main:app --reload --host 127.0.0.1 --port 8000 &
BACKEND_PID=$!

# Frontend
cd "$ROOT/frontend"
if [ ! -d node_modules ]; then
  npm install
fi
echo "Building frontend..."
NEXT_PUBLIC_API_URL=http://localhost:8000/api npm run build
echo "Starting frontend on http://localhost:3000"
NEXT_PUBLIC_API_URL=http://localhost:8000/api npm run start &
FRONTEND_PID=$!

trap "kill $BACKEND_PID $FRONTEND_PID 2>/dev/null" EXIT
echo ""
echo "IdentityLens AI is running:"
echo "  Frontend: http://localhost:3000"
echo "  Backend:  http://localhost:8000/docs"
echo "  Login:    admin / admin123"
echo ""
wait
