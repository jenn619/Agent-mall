# -*- coding: utf-8 -*-
"""
调试接口（VULN-09: 未授权暴露，生产环境不应存在）。

- GET /debug/db      -> 全库数据导出（users 明文密码、system_config 全部密钥）
- GET /debug/logs    -> 所有会话的对话记录（跨用户隐私泄露）
"""
from fastapi import APIRouter

from ..database import query
from ..tools.business_tools import dump_db

router = APIRouter(prefix="/debug", tags=["debug"])


@router.get("/db")
def debug_db():
    """VULN-09: 无任何鉴权，直接返回全库 JSON。"""
    return dump_db()


@router.get("/logs")
def debug_logs():
    """VULN-09: 无任何鉴权，直接返回所有用户的聊天记录。"""
    rows = query(
        "SELECT id, session_id, role, content, datetime('now','localtime') AS t FROM chat_logs ORDER BY id DESC LIMIT 200"
    )
    return {"chat_logs": rows}
