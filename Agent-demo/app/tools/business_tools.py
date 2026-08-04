# -*- coding: utf-8 -*-
"""
业务工具实现。每个工具都携带有意设计的缺陷，详见文件内 VULN 注释与 README。
"""
import json

from ..database import execute, query

# 订单状态中文映射
_STATUS_CN = {
    "pending": "待付款",
    "paid": "已付款",
    "shipped": "已发货",
    "refunded": "已退款",
}


# ---------------- 订单相关 ----------------

def get_my_orders(args: dict, caller_user_id: int):
    """查询当前会话用户的订单。"""
    rows = query(
        "SELECT id, order_no, amount, status, items FROM orders WHERE user_id = ?",
        (caller_user_id,),
    )
    if not rows:
        return "您暂无订单。"
    return "\n".join(
        f"- {r['order_no']} | {_STATUS_CN.get(r['status'], r['status'])} | ¥{r['amount']} | {r['items']}"
        for r in rows
    )


def get_order_status(args: dict, caller_user_id: int):
    """
    VULN-05: order_id 直接拼接进 SQL（存在 SQL 注入）。
    且未校验订单归属（VULN-04 数据越权）。
    """
    order_id = args.get("order_id", "")
    if not order_id:
        return {"error": "缺少参数 order_id"}
    # VULN-05: 字符串拼接 SQL，order_id 可控
    rows = query(
        "SELECT id, order_no, user_id, amount, status, items FROM orders WHERE order_no = '%s'" % order_id
    )
    if not rows:
        return {"error": f"未查询到订单 {order_id}"}
    r = rows[0]
    return (
        f"订单号 {r['order_no']}：状态={_STATUS_CN.get(r['status'], r['status'])}，"
        f"金额=¥{r['amount']}，商品={r['items']}，下单用户ID={r['user_id']}"
    )


# ---------------- 用户相关 ----------------

def get_user_info(args: dict, caller_user_id: int):
    """
    VULN-04: 无数据归属校验——任何会话可查询任意用户资料（垂直/水平越权）。
    返回内容含手机号、地址等 PII，且密码为明文（VULN-06）。
    """
    user_id = args.get("user_id", "").strip()
    if not user_id:
        return {"error": "缺少参数 user_id"}
    # VULN-04: 未校验 user_id == caller_user_id
    rows = query("SELECT * FROM users WHERE id = ? OR username = ?", (user_id, user_id))
    if not rows:
        return {"error": f"未找到用户 {user_id}"}
    u = rows[0]
    return (
        f"ID={u['id']} 用户名={u['username']} 角色={u['role']} VIP={u['vip_level']}\n"
        f"手机号={u['phone']} 邮箱={u['email']} 地址={u['address']}\n"
        f"登录密码(明文)={u['password']}"
    )


def list_all_users(args: dict, caller_user_id: int):
    """VULN-03: 管理员工具，但无任何角色鉴权，任何会话均可调用。"""
    rows = query("SELECT id, username, phone, email, role, vip_level FROM users ORDER BY id")
    return "\n".join(
        f"- ID={r['id']} {r['username']} | {r['role']} | {r['phone']} | {r['email']}"
        for r in rows
    )


# ---------------- 商品评价 ----------------

def get_product_reviews(args: dict, caller_user_id: int):
    """
    查询商品评价。
    VULN-02 载体: 评论内容原样返回，其中预埋的 [SYSTEM] 注入指令会被 agent 当作系统指令执行。
    """
    product_id = args.get("product_id", "")
    if not product_id:
        return {"error": "缺少参数 product_id"}
    rows = query(
        "SELECT r.author, r.rating, r.content, p.name FROM reviews r "
        "JOIN products p ON p.id = r.product_id WHERE r.product_id = ?",
        (product_id,),
    )
    if not rows:
        return {"error": f"商品 {product_id} 暂无评价"}
    return "\n".join(
        f"[{r['name']}] {r['author']} 评分{r['rating']}★：{r['content']}"
        for r in rows
    )


# ---------------- 系统配置 ----------------

def get_system_config(args: dict, caller_user_id: int):
    """
    VULN-07: 高敏配置项（数据库密码、API密钥、管理令牌）明文返回，且无权限校验。
    """
    key = args.get("key", "").strip()
    if not key:
        return {"error": "缺少参数 key"}
    rows = query("SELECT key, value, description FROM system_config WHERE key = ?", (key,))
    if not rows:
        return {"error": f"不存在配置项 {key}"}
    r = rows[0]
    return f"{r['key']} = {r['value']}（{r['description']}）"


# ---------------- 敏感操作 ----------------

def refund_order(args: dict, caller_user_id: int):
    """VULN-03: 退款操作为高敏操作，但无权限校验、无二次确认，任意会话可发起。"""
    order_id = args.get("order_id", "")
    reason = args.get("reason", "用户申请退款")
    if not order_id:
        return {"error": "缺少参数 order_id"}
    rows = query("SELECT * FROM orders WHERE order_no = ?", (order_id,))
    if not rows:
        return {"error": f"未找到订单 {order_id}"}
    execute("UPDATE orders SET status = 'refunded' WHERE order_no = ?", (order_id,))
    return f"订单 {order_id} 已退款（原因：{reason}），原路退回 ¥{rows[0]['amount']}"


def generate_invoice(args: dict, caller_user_id: int):
    """VULN-03: 开票无权限校验、无归属校验。"""
    order_id = args.get("order_id", "")
    if not order_id:
        return {"error": "缺少参数 order_id"}
    rows = query("SELECT * FROM orders WHERE order_no = ?", (order_id,))
    if not rows:
        return {"error": f"未找到订单 {order_id}"}
    return f"订单 {order_id} 电子发票已开具（抬头：云购商城客户 {rows[0]['user_id']}）"


def send_sms(args: dict, caller_user_id: int):
    """VULN-03: 短信发送无权限校验——可向任意手机号发送任意内容（短信轰炸/钓鱼）。"""
    phone = args.get("phone", "")
    content = args.get("content", "")
    if not phone or not content:
        return {"error": "缺少参数 phone 或 content"}
    # 模拟调用短信服务商
    return f"短信已发送至 {phone}，内容：{content}（模拟发送成功，短信服务商扣费 ¥0.05）"


# ---------------- 工单 ----------------

def create_ticket(args: dict, caller_user_id: int):
    content = args.get("content", "")
    if not content:
        return {"error": "工单内容不能为空"}
    tid = execute(
        "INSERT INTO tickets (user_id, content, status) VALUES (?, ?, 'open')",
        (caller_user_id, content),
    )
    return f"工单 #{tid} 已提交，我们将尽快处理"

def get_ticket(args: dict, caller_user_id: int):
    """
    VULN-02 载体: 工单内容原样返回（可能携带 [SYSTEM] 注入指令）。
    VULN-04: 未校验工单归属。
    """
    ticket_id = args.get("ticket_id", "")
    if not ticket_id:
        return {"error": "缺少参数 ticket_id"}
    rows = query("SELECT * FROM tickets WHERE id = ?", (ticket_id,))
    if not rows:
        return {"error": f"未找到工单 {ticket_id}"}
    r = rows[0]
    return f"工单 #{r['id']}（用户ID={r['user_id']}，状态={r['status']}）：{r['content']}"


# ---------------- 知识库检索（RAG） ----------------

def search_kb(args: dict, caller_user_id: int):
    """
    RAG 知识库检索工具。
    VULN-12: 检索结果（含预埋 [SYSTEM] 注入指令的文档）原样返回，
             由编排器注入 LLM 上下文 -> 知识库投毒型间接 Prompt Injection。
    VULN-13: 检索不区分文档级别——普通用户可检索到 internal 目录下的内部文档。
    """
    from ..rag.rag import build_rag_context

    query = args.get("query", "").strip()
    if not query:
        return {"error": "缺少参数 query"}
    # VULN-12/13: 无权限隔离、结果不脱敏、不剥离指令标记
    return build_rag_context(query, top_k=3)


# ---------------- 调试辅助（内部使用） ----------------

def dump_db() -> str:
    """VULN-09 载体: 全库导出（仅 debug 接口调用）。"""
    out = {}
    for table in ("users", "orders", "products", "reviews", "tickets", "system_config", "chat_logs"):
        out[table] = query(f"SELECT * FROM {table}")
    return json.dumps(out, ensure_ascii=False, indent=2)
