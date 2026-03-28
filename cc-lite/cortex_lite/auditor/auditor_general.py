import urllib.request
import urllib.error
import json
import re
import logging

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
- article: the article number — must be a quoted JSON string: "I", "II", or "IV", never a bare value
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

Do not issue findings for devices with insufficient evidence.
Do not upgrade suspicion level beyond what the evidence supports.
If no violations are found, return {{"findings": []}}.

CONSTITUTIONAL ARTICLES:
{self.constitution}"""

    def audit(self, registry_summary: list, gateway_ip: str, admin_id: str) -> list:
        # Build the user prompt once and reuse it
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
                {"role": "user", "content": user_prompt}
            ],
            "stream": False,
    # REMOVED: "format": "json"  ← crashes llama runner on CPU-only systems
            "options": {
                "num_ctx": 2048,   # ← caps context window to reduce memory footprint
                "num_gpu": 0  # force pure CPU, bypass GPU initialization entirely
            }
        }

        try:
            req = urllib.request.Request(self.api_url, method="POST")
            req.add_header("Content-Type", "application/json")
            data = json.dumps(payload).encode("utf-8")

            with urllib.request.urlopen(req, data=data, timeout=120) as response:
                result = json.loads(response.read().decode("utf-8"))
                raw_reply = result["message"]["content"]
                return self._parse_and_validate(raw_reply, registry_summary)

        except urllib.error.HTTPError as e:
            # Captures the 500 body so you can actually see what Ollama says
            body = e.read().decode("utf-8", errors="replace")
            logging.error(f"Ollama HTTP {e.code} at {self.api_url}: {body}")
            return []
        except urllib.error.URLError as e:
            logging.error(f"Failed to connect to Ollama at {self.api_url}: {e}")
            return []

    def _parse_and_validate(self, raw_reply: str, registry_summary: list) -> list:
        # Strip markdown fences the model insists on adding
        clean = raw_reply.strip()
        if clean.startswith("```"):
            clean = re.sub(r'^```[a-z]*\n?', '', clean)
            clean = re.sub(r'\n?```.*$', '', clean, flags=re.MULTILINE)
            clean = clean.strip()
        findings = []

        # Try 1: clean valid JSON object with "findings" key
        try:
            parsed = json.loads(raw_reply)
            if isinstance(parsed, dict) and "findings" in parsed:
                findings = parsed["findings"]
            elif isinstance(parsed, list):
                findings = parsed  # model ignored the wrapper, still usable
        except json.JSONDecodeError:
            pass

        # Try 2: extract object wrapper from surrounding text
        if not findings:
            match = re.search(r'\{.*?"findings"\s*:\s*(\[.*?\])\s*\}', raw_reply, re.DOTALL)
            if match:
                try:
                    findings = json.loads(match.group(1))
                except json.JSONDecodeError:
                    pass

        # Try 3: extract bare array (model ignored the wrapper entirely)
        if not findings:
            match = re.search(r'\[.*?\]', raw_reply, re.DOTALL)
            if match:
                try:
                    findings = json.loads(match.group(0))
                except json.JSONDecodeError:
                    pass

        if not findings:
            logging.error(f"Auditor returned unparseable output. Raw: {raw_reply[:300]}")
            return []

        # Validate findings (unchanged)
        valid_findings = []
        known_devices = {d["device_id"].replace(":", "").lower() for d in registry_summary}
        for f in findings:
            article   = f.get("article")
            device_id = f.get("device_id")
            suspicion = f.get("suspicion_level")
            if article not in self.valid_articles:
                logging.warning(f"Rejected finding: Invalid article {article}")
                continue
            device_id_normalized = f.get("device_id", "").replace(":", "").lower()
            if device_id_normalized not in known_devices:
                logging.warning(f"Rejected finding: Hallucinated device_id {f.get('device_id')}")
                continue
            if suspicion not in self.valid_suspicions:
                logging.warning(f"Rejected finding: Invalid suspicion_level {suspicion}")
                continue
            valid_findings.append(f)

        return valid_findings
