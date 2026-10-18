import requests
from django.conf import settings


def suggest_fix(finding):
    """Returns (text, provider). Output is advisory and model-generated, never a verified finding."""
    if settings.AI_PROVIDER == "anthropic" and settings.ANTHROPIC_API_KEY:
        prompt = (f"Vulnerability: {finding.title} ({finding.cwe}) at line {finding.line}.\n"
                  f"Code: {finding.evidence}\nExplain the risk briefly and show a corrected snippet.")
        try:
            r = requests.post("https://api.anthropic.com/v1/messages", timeout=30,
                              headers={"x-api-key": settings.ANTHROPIC_API_KEY, "anthropic-version": "2023-06-01",
                                       "content-type": "application/json"},
                              json={"model": settings.AI_MODEL, "max_tokens": 600,
                                    "messages": [{"role": "user", "content": prompt}]})
            r.raise_for_status()
            return r.json()["content"][0]["text"], "anthropic"
        except Exception:
            pass  # fall through to offline fallback
    text = (f"{finding.explanation}\n\nSuggested fix:\n{finding.remediation}"
            if finding.remediation else "Review this line manually against the linked CWE guidance.")
    return text, "offline-kb"
