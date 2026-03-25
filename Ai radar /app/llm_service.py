import os
import json
import re
from anthropic import Anthropic

DEFAULT_MODEL = "claude-sonnet-4-5"


def get_client():
    api_key = os.getenv("ANTHROPIC_API_KEY")
    if not api_key:
        return None
    return Anthropic(api_key=api_key)


def build_prompt(alert, result):
    return f"""
You are a SOC analyst assistant.

Your task is to help write a concise and professional triage response for a cybersecurity alert.

Alert context:
- Alert ID: {alert.get('id')}
- Timestamp: {alert.get('timestamp')}
- Event Type: {alert.get('event_type')}
- Source IP: {alert.get('src_ip')}
- Destination IP: {alert.get('dst_ip')}
- Protocol: {alert.get('protocol')}

Model output:
- Severity: {result.get('severity')}
- Risk Score: {result.get('score')}/5
- Confidence: {json.dumps(result.get('confidence', {}))}
- Recommended Action: {result.get('recommended_action')}
- False Positive Risk: {result.get('false_positive_risk')}

Top explainability factors:
{json.dumps(result.get('top_factors', []), indent=2)}

Return ONLY valid JSON.
Do not include markdown.
Do not include triple backticks.
Do not include any text before or after the JSON.

Return exactly these keys:
- analyst_explanation
- triage_summary
- false_positive_considerations
- next_steps

Rules:
- Be specific and analyst-friendly.
- Do not invent evidence not present in the alert.
- Mention uncertainty when appropriate.
- next_steps must be a JSON array of short strings.
- Keep each field concise.
"""


def extract_json_from_text(text: str):
    text = text.strip()

    try:
        return json.loads(text)
    except json.JSONDecodeError:
        pass

    fenced_match = re.search(r"```(?:json)?\s*(\{.*?\})\s*```", text, re.DOTALL)
    if fenced_match:
        candidate = fenced_match.group(1).strip()
        try:
            return json.loads(candidate)
        except json.JSONDecodeError:
            pass

    brace_match = re.search(r"\{.*\}", text, re.DOTALL)
    if brace_match:
        candidate = brace_match.group(0).strip()
        try:
            return json.loads(candidate)
        except json.JSONDecodeError:
            pass

    raise ValueError(f"Could not parse JSON from Claude response: {text}")


def normalize_next_steps(value):
    if isinstance(value, list):
        return [str(item).strip() for item in value if str(item).strip()]

    if isinstance(value, str):
        cleaned = value.strip()

        # Try parsing stringified JSON list
        try:
            parsed = json.loads(cleaned)
            if isinstance(parsed, list):
                return [str(item).strip() for item in parsed if str(item).strip()]
        except Exception:
            pass

        # Fallback: split numbered or sentence-like text
        if "\n" in cleaned:
            lines = [line.strip(" -•1234567890.").strip() for line in cleaned.splitlines()]
            lines = [line for line in lines if line]
            if lines:
                return lines

        return [cleaned] if cleaned else []

    return []


def generate_llm_triage(alert, result, model=DEFAULT_MODEL):
    client = get_client()

    if client is None:
        return {
            "analyst_explanation": result.get("ai_explanation", ""),
            "triage_summary": "LLM unavailable because ANTHROPIC_API_KEY is not set.",
            "false_positive_considerations": "Review confidence, supporting logs, and analyst context before escalation.",
            "next_steps": [
                "Validate the alert source.",
                "Review authentication and endpoint logs.",
                "Confirm whether escalation is necessary."
            ]
        }

    prompt = build_prompt(alert, result)

    try:
        response = client.messages.create(
            model=model,
            max_tokens=700,
            messages=[
                {
                    "role": "user",
                    "content": prompt
                }
            ]
        )

        text = "".join(
            block.text for block in response.content
            if getattr(block, "type", "") == "text"
        ).strip()

        data = extract_json_from_text(text)

        return {
            "analyst_explanation": data.get("analyst_explanation", result.get("ai_explanation", "")),
            "triage_summary": data.get("triage_summary", ""),
            "false_positive_considerations": data.get("false_positive_considerations", ""),
            "next_steps": normalize_next_steps(data.get("next_steps", []))
        }

    except Exception as e:
        return {
            "analyst_explanation": result.get("ai_explanation", ""),
            "triage_summary": f"Claude generation failed: {str(e)}",
            "false_positive_considerations": "Fallback mode active. Review supporting logs manually.",
            "next_steps": [
                result.get("recommended_action", "Review the alert manually.")
            ]
        }