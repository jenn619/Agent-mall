# -*- coding: utf-8 -*-
"""
AI-Agent 安全靶场启动入口
用法: python run.py
"""
import uvicorn

if __name__ == "__main__":
    uvicorn.run("app.main:app", host="0.0.0.0", port=8000, reload=False)
