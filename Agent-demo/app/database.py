# -*- coding: utf-8 -*-
"""
SQLite 数据库层。
注意: 表结构与访问方式均存在有意设计的缺陷，供安全练习使用。
"""
import sqlite3
import threading

from .config import DB_PATH

_lock = threading.Lock()


def get_conn():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
    with _lock:
        conn = get_conn()
        cur = conn.cursor()
        cur.executescript(
            """
            CREATE TABLE IF NOT EXISTS users (
                id          INTEGER PRIMARY KEY,
                username    TEXT NOT NULL,
                password    TEXT NOT NULL,          -- VULN: 明文密码存储
                phone       TEXT,
                email       TEXT,
                role        TEXT DEFAULT 'normal',  -- normal | admin
                vip_level   INTEGER DEFAULT 0,
                address     TEXT
            );

            CREATE TABLE IF NOT EXISTS sessions (
                id          TEXT PRIMARY KEY,       -- VULN: 会话ID格式可枚举(S{user_id}-{seq})
                user_id     INTEGER NOT NULL,
                created_at  TEXT DEFAULT (datetime('now', 'localtime'))
            );

            CREATE TABLE IF NOT EXISTS orders (
                id          INTEGER PRIMARY KEY,
                order_no    TEXT NOT NULL,
                user_id     INTEGER NOT NULL,
                amount      REAL NOT NULL,
                status      TEXT NOT NULL,          -- pending | paid | shipped | refunded
                items       TEXT
            );

            CREATE TABLE IF NOT EXISTS products (
                id          INTEGER PRIMARY KEY,
                name        TEXT NOT NULL,
                price       REAL NOT NULL,
                stock       INTEGER DEFAULT 0,
                description TEXT
            );

            CREATE TABLE IF NOT EXISTS reviews (
                id          INTEGER PRIMARY KEY,
                product_id  INTEGER NOT NULL,
                author      TEXT,
                rating      INTEGER,
                content     TEXT                   -- VULN: 评论内容可携带注入指令(间接Prompt Injection)
            );

            CREATE TABLE IF NOT EXISTS tickets (
                id          INTEGER PRIMARY KEY,
                user_id     INTEGER NOT NULL,
                content     TEXT,                  -- VULN: 工单内容可携带注入指令(间接Prompt Injection)
                status      TEXT DEFAULT 'open'
            );

            CREATE TABLE IF NOT EXISTS system_config (
                key         TEXT PRIMARY KEY,
                value       TEXT NOT NULL,
                description TEXT
            );

            CREATE TABLE IF NOT EXISTS chat_logs (
                id          INTEGER PRIMARY KEY AUTOINCREMENT,
                session_id  TEXT NOT NULL,
                role        TEXT NOT NULL,         -- user | agent | tool
                content     TEXT
            );
            """
        )
        conn.commit()
        conn.close()


def query(sql: str, args=()):
    """VULN: 直接拼接执行 SQL（调用方拼接字符串时存在注入），且无任何访问控制。"""
    with _lock:
        conn = get_conn()
        cur = conn.cursor()
        cur.execute(sql, args)
        rows = [dict(r) for r in cur.fetchall()]
        conn.close()
        return rows


def execute(sql: str, args=()):
    with _lock:
        conn = get_conn()
        cur = conn.cursor()
        cur.execute(sql, args)
        conn.commit()
        last_id = cur.lastrowid
        conn.close()
        return last_id


def log_chat(session_id: str, role: str, content: str):
    try:
        execute(
            "INSERT INTO chat_logs (session_id, role, content) VALUES (?, ?, ?)",
            (session_id, role, content),
        )
    except Exception:
        pass
