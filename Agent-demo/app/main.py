# -*- coding: utf-8 -*-
"""
AI-Agent 安全靶场主入口。
"""
from fastapi import FastAPI
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles

from .api import admin, chat, debug, session
from .config import RANGE_NAME, RANGE_VERSION
from .seed import seed

app = FastAPI(title=RANGE_NAME, version=RANGE_VERSION)

app.include_router(chat.router)
app.include_router(session.router)
app.include_router(debug.router)
app.include_router(admin.router)

app.mount("/static", StaticFiles(directory="app/static"), name="static")


@app.on_event("startup")
def on_startup():
    seed()


@app.get("/")
def index():
    return FileResponse("app/static/index.html")


@app.get("/api/health")
def health():
    return {"status": "ok", "range": RANGE_NAME, "version": RANGE_VERSION}
