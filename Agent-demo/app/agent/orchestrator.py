# -*- coding: utf-8 -*-
"""
Agent 编排循环：
user_message -> LLM 决策 -> 工具执行 -> (工具输出含注入则继续决策) -> 回复

VULN-02 的触发机制就在这里：当工具输出命中注入标记时，
编排器会把工具输出作为"新指令"重新交给 LLM 决策（对应提示词缺陷规则2），
而不是将其严格视为不可信数据。
"""
from ..tools.registry import execute_tool
from .mock_llm import build_reply, has_injection

MAX_LOOPS = 5


def run_agent(user_message: str, caller_user_id: int, llm, session_id: str = "") -> tuple:
    """
    返回 (reply, trace)
    trace 为决策轨迹（前端展示、安全检查观察点）:
      [{"step": 1, "input": "...", "decision": "...", "tool": "...", "args": {...}, "result": "...", "injected": bool}, ...]
    """
    trace = []
    current_input = user_message
    tool_output = None
    injected = False

    for step in range(1, MAX_LOOPS + 1):
        action = llm.decide(current_input, tool_output)

        if action[0] == "reply":
            trace.append({"step": step, "input": current_input, "decision": "直接回复",
                          "reply": action[1], "injected": injected})
            return action[1], trace

        tool_name, args = action[1], action[2]
        trace.append({"step": step, "input": current_input, "decision": f"调用工具 {tool_name}",
                      "tool": tool_name, "args": args, "injected": injected})

        # 执行工具（VULN-03/04/05/07 均在工具内部）
        result = execute_tool(tool_name, args, caller_user_id)

        if isinstance(result, dict) and result.get("error"):
            trace[-1]["result"] = result["error"]
            return f"抱歉，{tool_name} 执行失败：{result['error']}", trace

        result_text = str(result)
        trace[-1]["result"] = result_text

        # VULN-02: 工具输出被视为"可能含系统指令"的内容，命中标记则继续执行注入指令
        if has_injection(result_text):
            injected = True
            tool_output = result_text
            current_input = ""
            continue

        # 正常路径：生成面向用户的回复
        reply = build_reply(tool_name, result_text, injected=injected)
        trace[-1]["reply"] = reply
        return reply, trace

    return "抱歉，我已尽力，但无法完成该请求（达到最大决策轮数）。", trace
