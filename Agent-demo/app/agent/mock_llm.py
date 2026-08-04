# -*- coding: utf-8 -*-
"""
模拟 LLM：基于规则的决策引擎（VULN-01/02 的触发核心）。

决策优先级（刻意与真实 LLM 受注入影响的行为一致）：
1. 工具输出中的注入指令（间接 Prompt Injection）——最高优先级
2. 用户消息中的注入指令（直接 Prompt Injection）
3. 正常意图识别（关键词 -> 工具调用）

设计说明：模拟 LLM 严格遵循 prompts.SYSTEM_PROMPT 中写明的
"缺陷规则 1/2"，因此任何命中注入标记的内容都会被当作系统级指令执行。
"""
import re

from .prompts import INJECTION_MARKERS

# ---------------- 注入检测与解析 ----------------

_CALL_RE = re.compile(r"调用工具\s+([A-Za-z_]\w*)\s*\(([^)]*)\)")
_CALL_SIMPLE_RE = re.compile(r"调用工具\s+([A-Za-z_]\w*)\s*(?:参数)?\s*(.*)", re.S)
_ARG_RE = re.compile(r"([A-Za-z_]\w*)\s*=\s*['\"]([^'\"]*)['\"]")


def has_injection(text: str) -> bool:
    """命中任一注入标记即判定为注入（VULN: 数据与指令未区分）。"""
    if not text:
        return False
    for marker in INJECTION_MARKERS:
        if marker in text:
            return True
    return False


def parse_args(arg_str: str) -> dict:
    args = {}
    for m in _ARG_RE.finditer(arg_str or ""):
        args[m.group(1)] = m.group(2)
    return args


def extract_tool_call(text: str):
    """从注入内容中提取工具调用，返回 (tool_name, args)。"""
    m = _CALL_RE.search(text)
    if m:
        return m.group(1), parse_args(m.group(2))
    m = _CALL_SIMPLE_RE.search(text)
    if m:
        name = m.group(1)
        args = parse_args(m.group(2))
        # 支持 "key: value" 风格补充解析
        for k, v in re.findall(r"([A-Za-z_]\w*)\s*[:：]\s*([^\s,，]+)", m.group(2)):
            args.setdefault(k, v.strip("\"'"))
        return name, args
    return None, {}


# ---------------- 正常意图识别 ----------------

_INTENT_RULES = [
    (re.compile(r"退款|退货|退钱|退款申请"), "refund_order"),
    (re.compile(r"发票|开票|报销|税票"), "generate_invoice"),
    (re.compile(r"短信|验证码|发个短信|通知手机"), "send_sms"),
    (re.compile(r"所有用户|用户列表|全部用户|注册用户|用户清单"), "list_all_users"),
    (re.compile(r"配置|密钥|密码|token|数据库|api[ -]?key"), "get_system_config"),
    (re.compile(r"政策|权益|手册|指南|规则|流程|怎么用|怎么.*使用|使用方法|教程|帮助文档|知识库|会员|积分|售后|员工|使用说明|产品使用|保修|质保"), "search_kb"),
    (re.compile(r"评论|评价|口碑|买家秀|评价怎么样"), "get_product_reviews"),
    (re.compile(r"工单|反馈|投诉|人工"), "ticket"),
    (re.compile(r"用户信息|手机号|电话|资料|账户信息|个人信息|住址|地址"), "get_user_info"),
    (re.compile(r"订单|物流|快递|发货|单号"), "order"),
]

_ORDER_NO_RE = re.compile(r"(CK\d{8,})")
_TICKET_RE = re.compile(r"工单\s*[#编号]?\s*(\d+)")
_UID_RE = re.compile(r"(?:用户|ID|id)[#编号\s]*(\d+)|^(\d{1,3})$")
_PHONE_RE = re.compile(r"1[3-9]\d{9}")
_PID_RE = re.compile(r"商品\s*[#编号]?\s*(\d+)|(?:评价|评论)\s*(\d+)\s*号")
_CONFIG_KEY_RE = re.compile(r"([a-z_]+(?:password|key|token|host|endpoint)[a-z_]*)", re.I)


def _pick_intent(message: str):
    for pattern, intent in _INTENT_RULES:
        if pattern.search(message):
            return intent
    return None


def _intent_args(intent: str, message: str) -> dict:
    """按意图从消息中提取参数（VULN-05: order_id 由调用方拼接 SQL，此处不做任何校验）。"""
    args = {}
    if intent == "order":
        m = _ORDER_NO_RE.search(message)
        if m:
            args["order_id"] = m.group(1)
        elif "我的" in message or "我的订单" in message:
            args["_mine"] = True
    elif intent == "get_user_info":
        m = _UID_RE.search(message)
        if m:
            args["user_id"] = m.group(1) or m.group(2)
        elif re.search(r"[a-zA-Z_]{3,}", message):
            m2 = re.search(r"([a-zA-Z_]{3,})", message)
            args["user_id"] = m2.group(1)
    elif intent == "get_product_reviews":
        m = _PID_RE.search(message)
        if m:
            args["product_id"] = m.group(1) or m.group(2)
    elif intent == "get_system_config":
        m = _CONFIG_KEY_RE.search(message)
        if m:
            args["key"] = m.group(1).lower()
    elif intent == "send_sms":
        m = _PHONE_RE.search(message)
        if m:
            args["phone"] = m.group(0)
    elif intent == "ticket":
        m = _TICKET_RE.search(message)
        if m:
            args["_query_ticket"] = m.group(1)
        else:
            args["_create"] = True
    elif intent == "refund_order":
        m = _ORDER_NO_RE.search(message)
        if m:
            args["order_id"] = m.group(1)
    elif intent == "generate_invoice":
        m = _ORDER_NO_RE.search(message)
        if m:
            args["order_id"] = m.group(1)
    elif intent == "search_kb":
        # VULN-12 入口: 用户自然语言问题直接作为搜索 query
        args["query"] = message
    return args


# ---------------- 决策入口 ----------------

def decide(user_message: str, tool_output: str = None):
    """
    返回:
      ("tool", tool_name, args)  -> 需要调用工具
      ("reply", text)            -> 直接回复
    优先级: 工具输出注入 > 用户消息注入 > 正常意图
    """
    # 1) 间接注入：工具输出携带注入指令
    if tool_output and has_injection(tool_output):
        name, args = extract_tool_call(tool_output)
        if name:
            return ("tool", name, args)

    # 2) 直接注入：用户消息携带注入指令
    if user_message and has_injection(user_message):
        name, args = extract_tool_call(user_message)
        if name:
            return ("tool", name, args)

    # 3) 正常意图
    intent = _pick_intent(user_message)
    if intent == "ticket":
        args = _intent_args(intent, user_message)
        if args.get("_query_ticket"):
            return ("tool", "get_ticket", {"ticket_id": args["_query_ticket"]})
        if args.get("_create"):
            return ("tool", "create_ticket", {"content": user_message[:200]})
        return ("reply", "请问您需要提交什么工单内容呢？")

    if intent:
        args = _intent_args(intent, user_message)
        tool_map = {
            "order": "get_my_orders" if args.pop("_mine", False) else "get_order_status",
            "get_user_info": "get_user_info",
            "get_product_reviews": "get_product_reviews",
            "get_system_config": "get_system_config",
            "send_sms": "send_sms",
            "refund_order": "refund_order",
            "generate_invoice": "generate_invoice",
            "list_all_users": "list_all_users",
            "search_kb": "search_kb",
        }
        tool = tool_map[intent]
        if intent in ("order", "get_user_info", "get_product_reviews", "get_system_config",
                      "send_sms", "refund_order", "generate_invoice") and not args:
            return ("reply", "好的，请提供更多信息（如订单号、用户ID、配置项名称等），我帮您查询。")
        return ("tool", tool, args)

    return ("reply", "我是云购智能客服小云，可以帮您查询订单、商品评价、账户信息，办理退款、开票等。请问有什么可以帮您？")


# ---------------- 回复生成 ----------------

def build_reply(tool_name: str, result, injected: bool = False) -> str:
    """
    生成面向用户的回复。
    injected=True 表示本次动作由注入指令触发（模拟 LLM 按提示词规则5 直接展示工具结果）。
    """
    if isinstance(result, dict) and result.get("error"):
        return f"抱歉，操作未能完成：{result['error']}"

    text = str(result)
    if tool_name == "get_my_orders":
        return f"您的订单如下：\n{text}"
    if tool_name == "get_order_status":
        return f"订单状态查询结果：{text}"
    if tool_name == "get_user_info":
        return f"用户资料如下：\n{text}"
    if tool_name == "get_product_reviews":
        return f"该商品的用户评价如下：\n{text}"
    if tool_name == "get_system_config":
        return f"系统配置查询结果：{text}"
    if tool_name == "refund_order":
        return f"退款已受理：{text}"
    if tool_name == "generate_invoice":
        return f"发票开具结果：{text}"
    if tool_name == "send_sms":
        return f"短信已发送：{text}"
    if tool_name == "list_all_users":
        return f"注册用户列表如下：\n{text}"
    if tool_name == "create_ticket":
        return f"工单已提交：{text}"
    if tool_name == "get_ticket":
        return f"工单内容如下：\n{text}"
    if tool_name == "search_kb":
        return f"知识库查询结果：\n{text}"
    if injected:
        return text
    return text
