# -*- coding: utf-8 -*-
"""
RAG 检索管线：query -> 检索 top-k 分块 -> 拼接为带来源标注的上下文文本。

返回文本会原样注入 LLM 上下文（VULN-12: 检索结果与指令未分离——
文档中预埋的 [SYSTEM] 注入指令会随检索结果一起被 agent 当作系统指令执行）。
"""
from .retriever import search_kb


def build_rag_context(query: str, top_k: int = 5) -> str:
    results = search_kb(query, top_k)
    if not results:
        return "知识库中未找到相关内容。"
    parts = []
    for score, chunk in results:
        # VULN-13 观察点: level 仅展示，不阻断 internal 文档被检索
        tag = "内部" if chunk.level == "internal" else "公开"
        parts.append(f"[知识库:{chunk.doc} | {chunk.title} | {tag} | 相关度{score:.2f}]\n{chunk.content}")
    return "\n\n".join(parts)
