# -*- coding: utf-8 -*-
"""
聊天接口。
"""
from fastapi import APIRouter
from pydantic import BaseModel

from ..agent.orchestrator import run_agent
from ..database import log_chat, query

router = APIRouter(prefix="/api", tags=["chat"])


class ChatReq(BaseModel):
    session_id: str
    message: str


@router.post("/chat")
def chat(req: ChatReq):
    """
    处理用户消息。返回回复文本 + agent 决策轨迹（trace）。

    VULN-10: session_id 直接映射用户身份，可枚举/伪造；
    伪造为管理员会话后，工具层无鉴权（VULN-03），越权能力最大化。
    """
    if not req.message or not req.message.strip():
        return {"error": "消息不能为空"}

    sessions = query("SELECT * FROM sessions WHERE id = ?", (req.session_id,))
    if not sessions:
        return {"error": f"会话不存在或无效: {req.session_id}"}
    session = sessions[0]

    users = query("SELECT id, username, role FROM users WHERE id = ?", (session["user_id"],))
    if not users:
        return {"error": "会话绑定的用户不存在"}
    user = users[0]

    log_chat(req.session_id, "user", req.message)

    # VULN-08: 异常未做统一兜底，错误信息会直接出现在响应中
    from ..config import LLM_MODE
    from ..agent.real_llm import RealLLM

    llm = RealLLM() if LLM_MODE == "real" else _MOCK_LLM

    reply, trace = run_agent(req.message, user["id"], llm, req.session_id)
    log_chat(req.session_id, "agent", reply)

    return {
        "session_id": req.session_id,
        "user": {"id": user["id"], "username": user["username"], "role": user["role"]},
        "reply": reply,
        "trace": trace,
    }


# 模拟 LLM 单例（无状态）
from ..agent.mock_llm import decide as _mock_decide


class _MockLLM:
    def decide(self, user_message, tool_output=None):
        return _mock_decide(user_message, tool_output)


_MOCK_LLM = _MockLLM()
