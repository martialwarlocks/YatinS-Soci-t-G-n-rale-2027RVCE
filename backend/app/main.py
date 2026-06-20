from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from app.database import Base, SessionLocal, engine
from app.models import SystemMeta
from app.routers import auth, dashboard, identities, incidents, pipeline
from app.services.bootstrap import DATA_VERSION, bootstrap_database


@asynccontextmanager
async def lifespan(app: FastAPI):
    Base.metadata.create_all(bind=engine)
    db = SessionLocal()
    try:
        meta = db.query(SystemMeta).filter(SystemMeta.key == "data_version").first()
        force = not meta or meta.value != DATA_VERSION
        result = bootstrap_database(db, force=force)
        print(f"IdentityLens bootstrap: {result}")
    finally:
        db.close()
    yield


app = FastAPI(
    title="IdentityLens AI",
    description="Cross-Platform Identity Risk Intelligence Platform",
    version="1.0.0",
    lifespan=lifespan,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:3000", "http://frontend:3000", "*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(auth.router, prefix="/api")
app.include_router(dashboard.router, prefix="/api")
app.include_router(identities.router, prefix="/api")
app.include_router(incidents.router, prefix="/api")
app.include_router(pipeline.router, prefix="/api")


@app.get("/api/health")
def health():
    return {"status": "healthy", "service": "IdentityLens AI"}
