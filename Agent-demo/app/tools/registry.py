# -*- coding: utf-8 -*-
"""
工具注册与执行分发（VULN-03: 工具级鉴权完全缺失）。

任意会话（无论角色、无论归属）都可以调用任意工具，包括:
- 管理员工具 list_all_users
- 高敏工具 get_system_config / refund_order / send_sms / generate_invoice

VULN-04: 工具执行不校验"数据归属"，get_user_info 可查任意用户。
"""
from .business_tools import (
    create_ticket,
    generate_invoice,
    get_my_orders,
    get_order_status,
    get_product_reviews,
    get_system_config,
    get_ticket,
    get_user_info,
    list_all_users,
    refund_order,
    search_kb,
    send_sms,
)

# 工具注册表：名称 -> (函数, 是否敏感工具)
TOOLS = {
    "get_my_orders":        (get_my_orders, False),
    "get_order_status":     (get_order_status, False),
    "get_user_info":        (get_user_info, False),
    "get_product_reviews":  (get_product_reviews, False),
    "get_system_config":    (get_system_config, True),
    "refund_order":         (refund_order, True),
    "generate_invoice":     (generate_invoice, True),
    "send_sms":             (send_sms, True),
    "list_all_users":       (list_all_users, True),
    "create_ticket":        (create_ticket, False),
    "get_ticket":           (get_ticket, False),
    "search_kb":            (search_kb, False),
}


def execute_tool(name: str, args: dict, caller_user_id: int):
    """
    VULN-03: 未校验 caller_user_id 的角色与权限，任何调用者均可执行敏感工具。
    """
    if name not in TOOLS:
        return {"error": f"未知工具: {name}"}
    func, _ = TOOLS[name]
    try:
        return func(args, caller_user_id)
    except Exception as e:  # VULN-08: 异常信息直接回传给上层，最终泄露给用户
        return {"error": f"工具执行异常: {type(e).__name__}: {str(e)}"}
