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
        self.valid_articles = {"I", "II", "IV"}
        self.valid_suspicions = {"low", "medium", "high"}

    def _build_system_prompt(self) -> str:
        return f"""You are the Auditor General for a constitutional network governance system.
Your sole function is to evaluate network observations against the following
constitutional articles and identify potential violations.

You must return a JSON array of findings. Each finding must include:
- article: the article number (I, II, or IV)
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
If no violations are found, return an empty array [].

CONSTITUTIONAL ARTICLES:
{self.constitution}"""

    def audit(self, registry_summary: list, gateway_ip: str, admin_id: str) -> list:
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
                {"role": "user", "content": f"Gateway: {gateway_ip}\nAdmin: {admin_id}\nDevices: {json.dumps(registry_summary)}"}
            ],
            "stream": False,
            "format": "json" # Forces the model to output valid JSON
        }

        try:
            req = urllib.request.Request(self.api_url, method="POST")
            req.add_header("Content-Type", "application/json")
            data = json.dumps(payload).encode("utf-8")
            
            with urllib.request.urlopen(req, data=data) as response:
                result = json.loads(response.read().decode("utf-8"))
                raw_reply = result["message"]["content"]
                return self._parse_and_validate(raw_reply, registry_summary)
                
        except urllib.error.URLError as e:
            logging.error(f"Failed to connect to Ollama at {self.api_url}: {e}")
            return []

    def _parse_and_validate(self, raw_reply: str, registry_summary: list) -> list:
        # Extract JSON array using regex to bypass markdown fences (```json ... ```)
        match = re.search(r'\[\s*\{.*?\}\s*\]|\[\s*\]', raw_reply, re.DOTALL)
        if not match:
            logging.error(f"Auditor returned unparseable format. Raw output: {raw_reply}")
            return []

        try:
            findings = json.loads(match.group(0))
        except json.JSONDecodeError:
            logging.error(f"Extracted string is not valid JSON. Extracted: {match.group(0)}")
            return []

        # Validate findings
        valid_findings = []
        known_devices = {d["device_id"] for d in registry_summary}

        for f in findings:
            article = f.get("article")
            device_id = f.get("device_id")
            suspicion = f.get("suspicion_level")

            if article not in self.valid_articles:
                logging.warning(f"Rejected finding: Invalid article {article}")
                continue
            if device_id not in known_devices:
                logging.warning(f"Rejected finding: Hallucinated device_id {device_id}")
                continue
            if suspicion not in self.valid_suspicions:
                logging.warning(f"Rejected finding: Invalid suspicion_level {suspicion}")
                continue
                
            valid_findings.append(f)

        return valid_findings
