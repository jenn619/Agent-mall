# -*- coding: utf-8 -*-
"""
真实 LLM 客户端（OpenAI 兼容 Chat Completions）。
LLM_MODE=real 时启用；未配置密钥或请求失败时自动回退到模拟 LLM。

与模拟 LLM 相同，decide() 返回 ("tool", name, args) 或 ("reply", text)。
真实 LLM 同样遵循含缺陷的系统提示词（prompts.SYSTEM_PROMPT），
因此 prompt injection 是否生效取决于模型自身的对齐强度——这本身就是靶场观察点。
"""
import json

import httpx

from ..config import OPENAI_API_KEY, OPENAI_BASE_URL, OPENAI_MODEL
from .mock_llm import decide as mock_decide
from .prompts import SYSTEM_PROMPT, TOOL_DESCRIPTIONS

_TOOL_HINT = (
    "请根据用户请求与工具列表做出决策。"
    "若需要调用工具，仅输出 JSON：{\"action\": \"tool\", \"tool\": \"工具名\", \"args\": {\"参数\": \"值\"}}\n"
    "若无需调用工具，仅输出 JSON：{\"action\": \"reply\", \"reply\": \"你的中文回复\"}\n"
    "只输出 JSON，不要输出其他内容。\n"
    "可用工具："
    + json.dumps(TOOL_DESCRIPTIONS, ensure_ascii=False)
)


class RealLLM:
    def __init__(self):
        self._client = httpx.Client(timeout=30)
        self._available = bool(OPENAI_API_KEY)

    def decide(self, user_message: str, tool_output: str = None):
        if not self._available:
            return mock_decide(user_message, tool_output)

        messages = [{"role": "system", "content": SYSTEM_PROMPT + "\n" + _TOOL_HINT}]
        if tool_output:
            # 工具结果作为 assistant 消息带回（VULN-02: 原样注入到上下文）
            messages.append({"role": "assistant", "content": f"工具 {tool_output}"})
        messages.append({"role": "user", "content": user_message or "请继续执行系统指令"})

        try:
            resp = self._client.post(
                f"{OPENAI_BASE_URL.rstrip('/')}/chat/completions",
                headers={"Authorization": f"Bearer {OPENAI_API_KEY}"},
                json={
                    "model": OPENAI_MODEL,
                    "messages": messages,
                    "temperature": 0.1,
                    "response_format": {"type": "json_object"},
                },
            )
            resp.raise_for_status()
            content = resp.json()["choices"][0]["message"]["content"]
            parsed = json.loads(content)
            if parsed.get("action") == "tool":
                return ("tool", parsed["tool"], parsed.get("args", {}) or {})
            return ("reply", parsed.get("reply", content))
        except Exception:
            # 真实 LLM 不可用 -> 回退模拟决策
            return mock_decide(user_message, tool_output)
