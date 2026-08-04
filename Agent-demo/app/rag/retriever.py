# -*- coding: utf-8 -*-
"""
本地向量检索器：字符 bigram 特征 + TF 权重 + 余弦相似度。
零外部依赖、离线可用，中文/英文/混合内容均可检索。

说明：真实系统通常使用 embedding 模型（如 bge/text-embedding-3），
这里用 bigram 近似模拟向量检索行为，保证靶场离线可运行。
"""
import re
from collections import Counter

from .knowledge_base import load_chunks


def _tokens(text: str) -> list:
    """字符级 bigram（含空格归一化），并补充整词 token。"""
    norm = re.sub(r"\s+", "", text.lower())
    bigrams = [norm[i:i + 2] for i in range(len(norm) - 1)]
    words = re.findall(r"[a-z0-9]+", text.lower())
    return bigrams + words


def _tf_vector(text: str) -> Counter:
    return Counter(_tokens(text))


def _cosine(a: Counter, b: Counter) -> float:
    if not a or not b:
        return 0.0
    dot = sum((a & b).values())
    na = sum(v * v for v in a.values()) ** 0.5
    nb = sum(v * v for v in b.values()) ** 0.5
    return dot / (na * nb) if na and nb else 0.0


class Retriever:
    """VULN-13: 检索不感知权限——level 字段仅作展示，不参与过滤。"""

    def __init__(self):
        self.chunks = load_chunks()
        self.index = [(_tf_vector(c.text), c) for c in self.chunks]

    def search(self, query: str, top_k: int = 3) -> list:
        qv = _tf_vector(query)
        scored = sorted(
            ((_cosine(qv, vec), chunk) for vec, chunk in self.index),
            key=lambda x: x[0],
            reverse=True,
        )
        results = [(score, chunk) for score, chunk in scored if score > 0.02]
        return results[:top_k]


_retriever = Retriever()


def search_kb(query: str, top_k: int = 3) -> list:
    """供工具层调用的检索入口。"""
    return _retriever.search(query, top_k)
