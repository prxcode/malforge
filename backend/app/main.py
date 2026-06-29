# main.py

from contextlib import asynccontextmanager

import structlog
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import RedirectResponse

from app.auth.router import router as auth_router
from app.core.config import get_settings
from app.core.database import Base, engine
from app.core.storage import storage_service

settings = get_settings()
logger = structlog.get_logger()

# Import models to ensure they are registered with Base.metadata before create_all
from app.analysis.models import StaticAnalysisResult  # noqa: E402, F401
from app.detection.models import DetectionRule  # noqa: E402, F401
from app.ioc.models import IOCEntry  # noqa: E402, F401
from app.memory.models import MemoryAnalysisResult  # noqa: E402, F401
from app.reports.models import ThreatReport  # noqa: E402, F401
from app.samples.models import Sample  # noqa: E402, F401


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Lifecycle events for the FastAPI application."""
    logger.info("Starting up MAP API...")

    # Create all database tables automatically (replaces Alembic)
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)

    # Initialize storage (MinIO with local fallback)
    await storage_service.initialize()

    yield

    logger.info("Shutting down MAP API...")


def create_app() -> FastAPI:
    """Application factory."""
    app = FastAPI(
        title=settings.app_name,
        version=settings.app_version,
        openapi_url=f"{settings.api_prefix}/openapi.json",
        docs_url=f"{settings.api_prefix}/docs",
        redoc_url=f"{settings.api_prefix}/redoc",
        lifespan=lifespan,
    )

    # CORS configuration
    app.add_middleware(
        CORSMiddleware,
        allow_origins=settings.cors_origins,
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )

    # Include routers
    app.include_router(auth_router, prefix=settings.api_prefix)

    from app.samples.router import router as samples_router
    app.include_router(samples_router, prefix=settings.api_prefix)

    from app.analysis.router import router as analysis_router
    app.include_router(analysis_router, prefix=settings.api_prefix)

    from app.ioc.router import router as ioc_router
    app.include_router(ioc_router, prefix=settings.api_prefix)

    from app.detection.router import router as detection_router
    app.include_router(detection_router, prefix=settings.api_prefix)

    from app.memory.router import router as memory_router
    app.include_router(memory_router, prefix=settings.api_prefix)

    from app.reports.router import router as reports_router
    app.include_router(reports_router, prefix=settings.api_prefix)

    from app.orchestrator.router import router as orchestrator_router
    app.include_router(orchestrator_router, prefix=settings.api_prefix)

    # All core routers are now included.

    @app.get("/", include_in_schema=False)
    async def root():
        """Redirect root to API documentation."""
        return RedirectResponse(url=f"{settings.api_prefix}/docs")

    @app.get("/health", tags=["System"])
    async def health_check():
        """Basic health check endpoint."""
        return {
            "status": "ok",
            "service": settings.app_name,
            "version": settings.app_version,
        }

    return app


app = create_app()
