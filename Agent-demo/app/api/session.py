# -*- coding: utf-8 -*-
"""
会话管理接口。

VULN-10: 
- 创建会话时完全信任客户端传入的 user_id（身份伪造：可创建任意用户身份的会话，包括 admin）
- 会话ID格式为 S{user_id}-{seq}，可枚举
- /api/session/list 泄露全部会话ID
"""
from fastapi import APIRouter
from pydantic import BaseModel

from ..database import execute, query

router = APIRouter(prefix="/api/session", tags=["session"])


class NewSessionReq(BaseModel):
    # VULN-10: 客户端可任意指定身份绑定
    user_id: int = 2


class NewSessionResp(BaseModel):
    session_id: str
    user_id: int
    username: str
    role: str
    message: str


@router.post("/new", response_model=NewSessionResp)
def create_session(req: NewSessionReq):
    users = query("SELECT id, username, role FROM users WHERE id = ?", (req.user_id,))
    if not users:
        return {"error": "用户不存在"}
    u = users[0]
    seq = query("SELECT COUNT(*) AS c FROM sessions WHERE user_id = ?", (req.user_id,))[0]["c"] + 1
    # VULN-10: 会话ID可预测（S{user_id}-{seq}），无随机性、无签名
    session_id = f"S{req.user_id}-{seq}"
    execute("INSERT INTO sessions (id, user_id) VALUES (?, ?)", (session_id, req.user_id))
    return NewSessionResp(
        session_id=session_id,
        user_id=u["id"],
        username=u["username"],
        role=u["role"],
        message=f"会话创建成功，当前身份：{u['username']}（{u['role']}）",
    )


@router.get("/list")
def list_sessions():
    """VULN-10: 未授权列举所有会话ID（含管理员会话），可直接用于会话劫持/伪造。"""
    rows = query(
        "SELECT s.id AS session_id, s.user_id, u.username, u.role, s.created_at "
        "FROM sessions s JOIN users u ON u.id = s.user_id ORDER BY s.user_id"
    )
    return {"sessions": rows, "hint": "会话ID格式为 S{user_id}-{seq}"}
