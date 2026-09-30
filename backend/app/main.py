import logging
from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles

from app.api.routes import router
from app.core.config import get_settings
from app.jobs import ensure_worker
from app.service import init_database


@asynccontextmanager
async def lifespan(_app: FastAPI):
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
    init_database()
    stop = ensure_worker()
    yield
    stop.set()


app = FastAPI(title="钓鱼邮件知识图谱识别系统", lifespan=lifespan)
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:5173", "http://127.0.0.1:5173"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)
app.include_router(router, prefix="/api")
avatar_dir = get_settings().data_path / "avatar"
avatar_dir.mkdir(parents=True, exist_ok=True)
app.mount("/media/avatar", StaticFiles(directory=str(avatar_dir)), name="avatar")
