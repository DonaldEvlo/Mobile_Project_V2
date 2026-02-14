from contextlib import asynccontextmanager
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from app.core.config import get_settings
from app.core.database import init_db
from app.api.routes import security, auth, dashboard

settings = get_settings()


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Application lifespan — startup and shutdown events."""
    # ── Startup ──
    print(f"[API] Starting {settings.APP_NAME} v{settings.APP_VERSION}")

    # Initialize database tables
    print("[API] Initializing database...")
    await init_db()

    # Pre-load ML model
    print("[API] Loading ML model...")
    from app.ml.anomaly_detector import AnomalyDetector
    _detector = AnomalyDetector()  # noqa: F841
    print("[API] ML model ready")

    print(f"[API] Server ready on port 8000")

    yield

    # ── Shutdown ──
    print("[API] Shutting down...")


app = FastAPI(
    title=settings.APP_NAME,
    version=settings.APP_VERSION,
    description="Multi-layer APK attack detection system with AI-powered threat analysis.",
    lifespan=lifespan,
    docs_url="/docs",
    redoc_url="/redoc",
)

# ── CORS ──
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # Restrict in production
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ── Routes ──
app.include_router(security.router)
app.include_router(auth.router)
app.include_router(dashboard.router)


@app.get("/", tags=["Health"])
async def health_check():
    return {
        "status": "healthy",
        "service": settings.APP_NAME,
        "version": settings.APP_VERSION,
    }


@app.get("/api/health", tags=["Health"])
async def api_health():
    """Detailed health check including dependency status."""
    health = {
        "api": "healthy",
        "version": settings.APP_VERSION,
    }

    # Check database
    try:
        from app.core.database import async_session
        async with async_session() as session:
            await session.execute("SELECT 1")
        health["database"] = "healthy"
    except Exception:
        health["database"] = "unavailable"

    # Check Ollama
    try:
        import httpx
        async with httpx.AsyncClient(timeout=5) as client:
            resp = await client.get(f"{settings.OLLAMA_URL}/api/tags")
            health["ollama"] = "healthy" if resp.status_code == 200 else "unavailable"
    except Exception:
        health["ollama"] = "unavailable"

    return health
