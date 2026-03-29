import urllib.request
import urllib.error
import json
import re
import logging
import time


class AuditorGeneral:
    def __init__(self, model_name: str, constitution_text: str):
        self.model = model_name
        self.constitution = constitution_text
        self.api_url = "http://localhost:11434/api/chat"
        self.valid_articles = {"I", "II", "III", "IV", "V"}
        self.valid_suspicions = {"low", "medium", "high"}

    def _build_system_prompt(self) -> str:
        return f"""You are the Auditor General for a constitutional network governance system.
Your sole function is to evaluate network observations against the following
constitutional articles and identify potential violations.

You must return a JSON object with a single key "findings" containing an array.
Each finding in the array must include:
- article: the article number — must be a quoted JSON string: "I", "II", "III", "IV",
  or "V". Never a bare value, never prefixed with "Article".
- device_id: the device identifier from the observation
- suspicion_level: one of [low, medium, high]
- evidence: a one-sentence description of what you observed
- reasoning: a one-sentence explanation of why this may violate the article

suspicion_level rules:
- high: IoT-classified device observed communicating with a non-gateway
  MAC on the same L2 segment that is classified as a private asset
- medium: IoT-classified device present on same L2 as private assets,
  with RFC1918 destination that is not the known gateway
- low: Device classification is uncertain but warrants monitoring

Explicit constraints — apply strictly:
- Article I applies ONLY when an action would directly sever the Administrator's
  connection to the network. A device merely being present or unknown is NOT
  an Article I violation. The Admin device itself is never a violation.
- Article II applies ONLY when a private asset's path to the Gateway is blocked
  or interrupted. IoT devices on the L2 segment are Article IV, not Article II.
- Article III applies to devices with unknown or unresolvable OUI. Do not
  escalate Article III findings to other articles.
- Article IV applies to IoT-classified devices present on or communicating
  with the Private VLAN. This is the correct article for isolation violations.
- Article V applies only when audit logging is demonstrably absent. Do not
  issue Article V findings based on device classification uncertainty.
- Never file a finding against the Admin device MAC unless it is actively
  being impersonated by another device.

Do not issue findings for devices with insufficient evidence.
Do not upgrade suspicion level beyond what the evidence supports.
If no violations are found, return {{"findings": []}}.

CONSTITUTIONAL ARTICLES:
{self.constitution}"""

    def audit(self, registry_summary: list, gateway_ip: str, admin_id: str) -> dict:
        """
        Returns a dict containing:
          - valid_findings: list of validated finding dicts
          - rejected_findings: list of dicts with 'finding' and 'reason'
          - raw_reply: the raw string from the model
          - duration_seconds: float
          - error: string or None
        """
        user_prompt = f"""Network observation summary:
- Gateway IP: {gateway_ip}
- Admin device MAC hash: {admin_id}
- Observed devices: {len(registry_summary)}

Device list:
{json.dumps(registry_summary, indent=2)}
"""
        payload = {
            "model": self.model,
            "messages": [
                {"role": "system", "content": self._build_system_prompt()},
                {"role": "user",   "content": user_prompt}
            ],
            "stream": False,
            "options": {
                "num_ctx": 2048,
                "num_gpu": 0,
                "temperature": 0.2
            }
        }

        t0 = time.time()
        try:
            req = urllib.request.Request(self.api_url, method="POST")
            req.add_header("Content-Type", "application/json")
            data = json.dumps(payload).encode("utf-8")

            with urllib.request.urlopen(req, data=data, timeout=180) as response:
                result = json.loads(response.read().decode("utf-8"))
                raw_reply = result["message"]["content"]
                duration = round(time.time() - t0, 2)
                valid, rejected = self._parse_and_validate(raw_reply, registry_summary)
                return {
                    "valid_findings": valid,
                    "rejected_findings": rejected,
                    "raw_reply": raw_reply,
                    "duration_seconds": duration,
                    "error": None
                }

        except urllib.error.HTTPError as e:
            body = e.read().decode("utf-8", errors="replace")
            msg = f"Ollama HTTP {e.code}: {body}"
            logging.error(msg)
            return self._error_result(msg, time.time() - t0)

        except urllib.error.URLError as e:
            msg = f"Failed to connect to Ollama: {e}"
            logging.error(msg)
            return self._error_result(msg, time.time() - t0)

        except Exception as e:
            msg = f"Unexpected error: {e}"
            logging.error(msg)
            return self._error_result(msg, time.time() - t0)

    def _error_result(self, msg: str, elapsed: float) -> dict:
        return {
            "valid_findings": [],
            "rejected_findings": [],
            "raw_reply": "",
            "duration_seconds": round(elapsed, 2),
            "error": msg
        }

    def _parse_and_validate(self, raw_reply: str, registry_summary: list) -> tuple[list, list]:
        """Returns (valid_findings, rejected_findings)."""
        findings = []

        clean = raw_reply.strip()
        if clean.startswith("```"):
            clean = re.sub(r'^```[a-z]*\n?', '', clean)
            clean = re.sub(r'\n?```.*$', '', clean, flags=re.MULTILINE)
            clean = clean.strip()

        # Try 1: valid JSON object with "findings" key
        try:
            parsed = json.loads(clean)
            if isinstance(parsed, dict) and "findings" in parsed:
                findings = parsed["findings"]
            elif isinstance(parsed, list):
                findings = parsed
        except json.JSONDecodeError:
            pass

        # Try 2: extract findings array from surrounding text
        if not findings:
            match = re.search(
                r'\{.*?"findings"\s*:\s*(\[.*?\])\s*\}', clean, re.DOTALL
            )
            if match:
                try:
                    findings = json.loads(match.group(1))
                except json.JSONDecodeError:
                    pass

        # Try 3: bare array
        if not findings:
            match = re.search(r'\[.*?\]', clean, re.DOTALL)
            if match:
                try:
                    findings = json.loads(match.group(0))
                except json.JSONDecodeError:
                    pass

        if not findings:
            logging.error(f"Auditor returned unparseable output. Raw: {raw_reply[:300]}")
            return [], []

        valid_findings = []
        rejected_findings = []
        known_devices = {d["device_id"].replace(":", "").lower() for d in registry_summary}

        for f in findings:
            # Normalize article value
            article = f.get("article", "").strip().upper()
            if article.startswith("ARTICLE "):
                article = article.replace("ARTICLE ", "").strip()
            f["article"] = article

            device_id = f.get("device_id", "")
            suspicion = f.get("suspicion_level")
            device_id_normalized = device_id.replace(":", "").lower()

            if article not in self.valid_articles:
                rejected_findings.append({"finding": f, "reason": f"Invalid article: {article}"})
                logging.warning(f"Rejected finding: Invalid article {article}")
                continue
            if device_id_normalized not in known_devices:
                rejected_findings.append({"finding": f, "reason": f"Hallucinated device_id: {device_id}"})
                logging.warning(f"Rejected finding: Hallucinated device_id {device_id}")
                continue
            if suspicion not in self.valid_suspicions:
                rejected_findings.append({"finding": f, "reason": f"Invalid suspicion_level: {suspicion}"})
                logging.warning(f"Rejected finding: Invalid suspicion_level {suspicion}")
                continue

            valid_findings.append(f)

        return valid_findings, rejected_findings
