import asyncio
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from src.api.routes import auth_routes, fim_routes
from src.api.database.connection import AuthBase, FimBase, auth_engine, fim_engine, test_connections
from src.api.models import user_model, fim_models
from src.FIM.fim_shared import get_fim_loop, set_fim_loop
from src.utils.thread_pool import thread_pool

app = FastAPI(title="File Integrity Monitoring API")

# Fix CORS - Add all your frontend URLs
app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "http://localhost:3000",
        "http://localhost:8080",
        "http://127.0.0.1:3000",
        "http://127.0.0.1:8080",
    ],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Include routes
app.include_router(auth_routes.router)
app.include_router(fim_routes.router)

@app.on_event("startup")
async def on_startup():
    """
    Automatically create all required database tables at startup.
    """
    # Test database connections first
    test_connections()

    AuthBase.metadata.create_all(bind=auth_engine)
    FimBase.metadata.create_all(bind=fim_engine)

    loop = asyncio.get_running_loop()
    set_fim_loop(loop)

@app.on_event("shutdown")
def on_shutdown():
    """Cleanup resoueces on shutdown."""
    print("Shutting down FIM resources...")
    thread_pool.shutdown(wait=True)
    print("FIM resources cleanup complete.")

@app.get("/")
def root():
    return {"message": "File Integrity Monitoring API is running!"}
