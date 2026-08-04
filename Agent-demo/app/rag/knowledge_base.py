# -*- coding: utf-8 -*-
"""
知识库文档加载与分块。

文档目录:
    docs/            公开文档
    docs/internal/   内部文档（VULN-13: 检索层不做权限隔离，任何会话都能检索到）

分块规则: 按 "## " 二级标题分块，每块携带来源与级别元数据。
"""
import os
import re

DOCS_DIR = os.path.join(os.path.dirname(__file__), "docs")


class Chunk:
    def __init__(self, doc: str, title: str, content: str, level: str, path: str):
        self.doc = doc          # 文档名（不含扩展名）
        self.title = title      # 分块标题
        self.content = content  # 分块正文
        self.level = level      # public | internal（VULN-13: 检索时未使用该字段过滤）
        self.path = path        # 相对 docs 的路径

    @property
    def text(self):
        return f"{self.title}\n{self.content}"

    def __repr__(self):
        return f"<Chunk {self.doc}/{self.title} [{self.level}]>"


def load_chunks() -> list:
    chunks = []
    for root, _, files in os.walk(DOCS_DIR):
        for fname in files:
            if not fname.endswith(".md"):
                continue
            fpath = os.path.join(root, fname)
            rel = os.path.relpath(fpath, DOCS_DIR)
            level = "internal" if rel.startswith("internal") else "public"
            doc_name = os.path.splitext(fname)[0]
            with open(fpath, "r", encoding="utf-8") as f:
                content = f.read()
            # 按二级标题分块
            parts = re.split(r"(?m)^## ", content)
            header = parts[0].strip()  # 文档标题区
            for part in parts[1:]:
                lines = part.strip().splitlines()
                title = lines[0].strip()
                body = "\n".join(lines[1:]).strip()
                chunks.append(Chunk(doc_name, title, body, level, rel))
            # 无二级标题的文档：整篇作为一块
            if len(parts) == 1 and header:
                chunks.append(Chunk(doc_name, doc_name, header, level, rel))
    return chunks
