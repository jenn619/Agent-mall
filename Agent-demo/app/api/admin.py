# -*- coding: utf-8 -*-
"""
管理员导出接口。

VULN-11: 访问令牌 admin_token 明文存放在 system_config 中，
攻击者可通过 get_system_config 工具（VULN-07）或 /debug/db（VULN-09）
获取该令牌，从而调用本接口导出全部订单与用户数据（完整攻击链）。
"""
from fastapi import APIRouter, Header

from ..database import query
from ..tools.business_tools import dump_db

router = APIRouter(prefix="/api/admin", tags=["admin"])


@router.post("/export")
def admin_export(x_admin_token: str = Header(default="", alias="X-Admin-Token")):
    """导出全部业务数据（订单+用户+配置）。"""
    rows = query("SELECT value FROM system_config WHERE key = 'admin_token'")
    expected = rows[0]["value"] if rows else ""
    if x_admin_token != expected:
        return {"error": "forbidden: invalid admin token"}
    return {"exported": True, "data": dump_db()}
