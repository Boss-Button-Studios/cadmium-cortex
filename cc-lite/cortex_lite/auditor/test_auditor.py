from cortex_lite.auditor.auditor_general import AuditorGeneral

# Mock data
test_registry = [{"device_id": "9009d051edf0", "ip": "192.168.0.5", "mac": "90:09:d0:51:ed:f0", "vendor": "Dell"}]
const_text = "ARTICLE IV: IoT-classified devices must be logically isolated."

auditor = AuditorGeneral("qwen2.5-coder:1.5b", const_text)
findings = auditor.audit(test_registry)
print(f"Findings: {findings}")
