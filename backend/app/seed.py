PHISH_BODIES = [
    "您的账户存在异常登录，请立即验证身份并重置密码。若 12 小时内未处理，账户将被冻结。",
    "工资补贴已到账，请核对收款账户并确认身份信息，逾期将退回款项。",
    "发票校验失败，请下载附件并登录安全中心重新提交企业认证。",
    "邮箱容量已满，无法继续收信。请立刻升级存储并确认管理员密码。",
    "检测到异地支付，请确认是否为本人操作，否则资金将被暂停结算。",
    "Your mailbox will be suspended today. Verify the password and update billing details immediately.",
    "Unusual sign-in detected. Confirm your identity to avoid permanent account lock.",
    "Payroll deposit failed. Review the bank account and verify the security code now.",
    "Shared document requires your password. Open the secure portal before the link expires.",
    "Package duty is unpaid. Confirm the payment card to release the shipment today.",
]
HAM_BODIES = [
    "明天下午三点在会议室同步项目进度，请提前阅读需求纪要并准备问题清单。",
    "本周代码评审改到周四，关注登录模块的异常处理和单元测试覆盖率。",
    "附件是上周会议纪要，结论是先完成数据清洗再讨论模型参数，无需额外审批。",
    "请把接口文档补全到仓库，重点说明请求字段、错误码和示例响应。",
    "实验室服务器今晚维护，训练任务请避开 23 点到次日 6 点。",
    "The design review is scheduled for Thursday. Please read the notes and bring open questions.",
    "I pushed the API documentation. The examples cover request fields and error codes.",
    "Sprint planning stays on Monday. We will estimate the export task and the empty states.",
    "The lab machine reboots tonight. Move long jobs away from the maintenance window.",
    "Thanks for the meeting notes. I will update the schedule and share the revised timeline.",
]


def sample_rows() -> list[dict]:
    rows = []
    for index, body in enumerate(PHISH_BODIES):
        domain = "paypa1.com" if index % 2 == 0 else "micr0soft.com"
        sender = f"billing{index % 3}@paypa1.com"
        url = f"http://{domain}/login?id={index}"
        extra = " redirects to http://203.0.113.10/pay" if index == 0 else ""
        rows.append({
            "subject": f"账户安全验证 {index + 1}",
            "body": f"{body} 请打开 {url} 完成验证。{extra}",
            "from_addr": sender,
            "label": "phish",
        })
    for index, body in enumerate(HAM_BODIES):
        url = f"https://github.com/phishkg/docs/{index}" if index % 2 == 0 else f"https://company.com/wiki/{index}"
        rows.append({
            "subject": f"项目沟通 {index + 1}",
            "body": f"{body} 参考 {url}",
            "from_addr": f"member{index % 3}@company.com",
            "label": "ham",
        })
    return rows


DEMO_CERTS = [
    ("paypa1.com", "Demo Untrusted CA"),
    ("micr0soft.com", "Demo Untrusted CA"),
    ("github.com", "DigiCert Inc"),
    ("company.com", "Company Internal CA"),
]
