import urllib.request
import urllib.error
import json
import re
import logging
import time


class AuditorGeneral:
    def __init__(self, model_name: str, constitution_text: str):
        self.model        = model_name
        self.constitution = constitution_text
        self.api_url      = "http://localhost:11434/api/chat"

        # CC-Lite passive observation scope.
        # Articles I and II require active enforcement context (Sheriff).
        # They cannot be triggered by passive observation and are excluded
        # at the architecture level, not just by prompt constraint.
        self.valid_articles   = {"III", "IV"}
        self.valid_suspicions = {"low", "medium", "high"}

    # -----------------------------------------------------------------------
    # Prompt v5
    # -----------------------------------------------------------------------

    def _build_system_prompt(self) -> str:
        return f"""You are the Auditor General for a constitutional network governance system
operating in passive observation mode.

Your jurisdiction covers two articles only:
  Article III — SILENCE: devices with unknown or unresolvable identity
  Article IV  — ISOLATION: IoT devices not isolated from the Private segment

You have NO jurisdiction over Articles I, II, or V in passive observation mode.
Do not file findings under those articles under any circumstances.

--- DEVICE CLASSIFICATION ---

Each device in the observation has a pre-computed classification:
  Infrastructure — gateway, WAPs, switches. NOT a finding target.
  Admin          — the administrator's device. NOT a finding target.
  IoT            — smart home devices, cameras, appliances. Article IV scope.
  Unknown-Random — randomized MAC (locally_administered: true). Article III only,
                   suspicion never above "low".
  Unknown        — unresolvable OUI, no identifying signals. Article III scope.
  Private        — laptops, phones, NAS. NOT a finding target in passive mode.

Only IoT, Unknown-Random, and Unknown devices may appear in findings.
If a device is classified Infrastructure, Admin, or Private — skip it entirely.

--- ARTICLE DECISION RULES ---

Article IV — file when:
  - device_class is "IoT"
  - AND the device is present on the same L2 segment as private assets
  Suspicion levels:
    high:   IoT device observed communicating with a non-gateway RFC1918 address
    medium: IoT device present on Private L2 with any RFC1918 destination
    low:    IoT device present on Private L2, destination uncertain

Article III — file when:
  - device_class is "Unknown" or "Unknown-Random"
  - AND the device appears to be initiating peer-to-peer sessions
  Suspicion levels:
    high:   Unknown device communicating with multiple private assets
    medium: Unknown device with RFC1918 destination that is not the gateway
    low:    Unknown device present, classification uncertain
  Hard constraint: Unknown-Random devices never exceed "low" suspicion.

--- OUTPUT FORMAT ---

Return a JSON object with a single key "findings" containing an array.
Each finding must include:
  - article:         "III" or "IV" — a quoted string, never bare
  - device_id:       the device_id from the observation
  - suspicion_level: "low", "medium", or "high"
  - evidence:        one sentence describing what was observed
  - reasoning:       one sentence explaining the constitutional basis

If no violations are found, return {{"findings": []}}.
Do not include findings for Infrastructure, Admin, or Private devices.
Do not include findings under Articles I, II, or V.

CONSTITUTIONAL ARTICLES (reference only — your jurisdiction is III and IV):
{self.constitution}"""

    # -----------------------------------------------------------------------
    # Audit
    # -----------------------------------------------------------------------

    def audit(self, dossiers: list, gateway_ip: str, admin_id: str) -> dict:
        """
        Run a constitutional audit on a batch of device dossiers.

        Parameters
        ----------
        dossiers   : list of dicts (DeviceDossier.to_dict()) — pre-classified
        gateway_ip : gateway IP address
        admin_id   : admin MAC address (excluded from findings in user prompt)

        Returns a dict containing:
          - valid_findings:     list of validated finding dicts
          - rejected_findings:  list of dicts with 'finding' and 'reason'
          - raw_reply:          raw model output string
          - tokens:             dict with prompt_tokens, completion_tokens, total_tokens
          - duration_seconds:   float
          - error:              string or None
        """
        # Admin and gateway exclusions stated explicitly in user prompt
        # so the model sees them right next to the device list
        user_prompt = f"""EXCLUDED FROM ALL FINDINGS — do not file under any article:
  - {admin_id} (Administrator device)
  - {gateway_ip} (Gateway — infrastructure, not a violation target)

Network observation:
  Gateway IP     : {gateway_ip}
  Devices observed: {len(dossiers)}

Device dossiers:
{json.dumps(dossiers, indent=2)}
"""
        payload = {
            "model": self.model,
            "messages": [
                {"role": "system", "content": self._build_system_prompt()},
                {"role": "user",   "content": user_prompt},
            ],
            "stream": False,
            "options": {
                "num_ctx":     2048,
                "num_gpu":     0,
                "temperature": 0.2,
            },
        }

        empty_tokens = {"prompt_tokens": 0, "completion_tokens": 0, "total_tokens": 0}
        t0 = time.time()

        try:
            req = urllib.request.Request(self.api_url, method="POST")
            req.add_header("Content-Type", "application/json")
            data = json.dumps(payload).encode("utf-8")

            with urllib.request.urlopen(req, data=data, timeout=180) as response:
                result = json.loads(response.read().decode("utf-8"))

            raw_reply = result["message"]["content"]
            duration  = round(time.time() - t0, 2)

            prompt_tokens     = result.get("prompt_eval_count", 0)
            completion_tokens = result.get("eval_count", 0)
            tokens = {
                "prompt_tokens":     prompt_tokens,
                "completion_tokens": completion_tokens,
                "total_tokens":      prompt_tokens + completion_tokens,
            }

            valid, rejected = self._parse_and_validate(raw_reply, dossiers)
            return {
                "valid_findings":    valid,
                "rejected_findings": rejected,
                "raw_reply":         raw_reply,
                "tokens":            tokens,
                "duration_seconds":  duration,
                "error":             None,
            }

        except urllib.error.HTTPError as e:
            body = e.read().decode("utf-8", errors="replace")
            msg  = f"Ollama HTTP {e.code}: {body}"
            logging.error(msg)
            return self._error_result(msg, time.time() - t0, empty_tokens)

        except urllib.error.URLError as e:
            msg = f"Failed to connect to Ollama: {e}"
            logging.error(msg)
            return self._error_result(msg, time.time() - t0, empty_tokens)

        except Exception as e:
            msg = f"Unexpected error: {e}"
            logging.error(msg)
            return self._error_result(msg, time.time() - t0, empty_tokens)

    def _error_result(self, msg: str, elapsed: float, tokens: dict) -> dict:
        return {
            "valid_findings":    [],
            "rejected_findings": [],
            "raw_reply":         "",
            "tokens":            tokens,
            "duration_seconds":  round(elapsed, 2),
            "error":             msg,
        }

    # -----------------------------------------------------------------------
    # Parse and validate
    # -----------------------------------------------------------------------

    def _parse_and_validate(self, raw_reply: str, dossiers: list) -> tuple:
        """Returns (valid_findings, rejected_findings)."""
        findings = []

        clean = raw_reply.strip()
        if clean.startswith("```"):
            clean = re.sub(r'^```[a-z]*\n?', '', clean)
            clean = re.sub(r'\n?```.*$', '', clean, flags=re.MULTILINE)
            clean = clean.strip()

        # Try 1: JSON object with "findings" key
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

        valid_findings    = []
        rejected_findings = []

        known_devices = {
            d["device_id"].replace(":", "").lower()
            for d in dossiers
            if d.get("device_id") is not None
        }

        for f in findings:
            # Normalize article
            article = f.get("article", "")
            if isinstance(article, str):
                article = article.strip().upper()
                if article.startswith("ARTICLE "):
                    article = article.replace("ARTICLE ", "").strip()
            f["article"] = article

            device_id            = f.get("device_id", "") or ""
            suspicion            = f.get("suspicion_level")
            device_id_normalized = device_id.replace(":", "").lower()

            if article not in self.valid_articles:
                rejected_findings.append(
                    {"finding": f, "reason": f"Out-of-scope article: {article}"}
                )
                logging.warning(f"Rejected finding: out-of-scope article {article}")
            elif device_id_normalized not in known_devices:
                rejected_findings.append(
                    {"finding": f, "reason": f"Hallucinated device_id: {device_id}"}
                )
                logging.warning(f"Rejected finding: hallucinated device_id {device_id}")
            elif suspicion not in self.valid_suspicions:
                rejected_findings.append(
                    {"finding": f, "reason": f"Invalid suspicion_level: {suspicion}"}
                )
                logging.warning(f"Rejected finding: invalid suspicion_level {suspicion}")
            else:
                valid_findings.append(f)

        return valid_findings, rejected_findings
