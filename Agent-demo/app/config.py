# -*- coding: utf-8 -*-
"""
靶场全局配置。
LLM 模式切换:
    LLM_MODE=mock   -> 本地模拟 LLM（默认，离线可用、行为确定）
    LLM_MODE=real   -> 真实 LLM（需配置 OPENAI_BASE_URL / OPENAI_API_KEY / OPENAI_MODEL）
"""
import os

DB_PATH = os.environ.get("RANGE_DB_PATH", os.path.join(os.path.dirname(__file__), "range.db"))

LLM_MODE = os.environ.get("LLM_MODE", "real")          # 改为 real 以使用真实 API
OPENAI_BASE_URL = os.environ.get("OPENAI_BASE_URL", "https://api.deepseek.com")  # DeepSeek 的基础 URL [citation:3][citation:11]
OPENAI_API_KEY = os.environ.get("OPENAI_API_KEY", "sk-133c1e28970f43c78563bd27f85d054a")  # 从 DeepSeek 平台获取的 API Key [citation:1][citation:3]
OPENAI_MODEL = os.environ.get("OPENAI_MODEL", "deepseek-v4-flash")  # Flash 模型名称 [citation:2][citation:5][citation:7]

# ---- 靶场元信息（用于前端展示）----
RANGE_NAME = "云购 AI 客服智能体安全靶场"
RANGE_VERSION = "1.0.0"
