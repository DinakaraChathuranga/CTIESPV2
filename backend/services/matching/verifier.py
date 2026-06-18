"""
OpenAI-powered manual match verification.

This is user-initiated by an analyst from the alert page.
It does NOT approve or reject alerts automatically.
It only returns and stores the AI verdict, confidence, reason, and recommendation.
"""

import json
import logging
from core.config import settings

logger = logging.getLogger(__name__)

SYSTEM_PROMPT = """
You are a senior cybersecurity analyst verifying whether a CVE affects a specific client asset.
Return only valid JSON. Do not include markdown.
"""

USER_PROMPT = """
Determine whether the CVE below directly affects the listed client asset.

CVE ID:
{cve_id}

CVE Title:
{title}

CVE Description:
{description}

Affected Products from CVE/NVD:
{affected_products}

CPE Strings:
{cpe_strings}

Vulnerability Type:
{vuln_type}

Client:
{client_name}

Matched Asset:
{asset_name}

Current Matching Method:
{match_method}

Current Matching Score:
{match_score}

Rules:
1. Same vendor is not enough. The exact product or product family must be affected.
2. A Fortinet FortiOS CVE should not match FortiAnalyzer, FortiManager, FortiClient, or FortiSandbox unless those products are explicitly affected.
3. A FortiSandbox CVE should not match FortiClient, FortiAnalyzer, FortiManager, or FortiGate unless explicitly affected.
4. A Microsoft SharePoint CVE should not match Windows 10/11 or generic Microsoft 365 unless SharePoint/SharePoint Online is clearly affected.
5. A Windows kernel, Win32K, TCP/IP, Event Log, or driver CVE should match Windows OS assets, not Microsoft 365 cloud service.
6. Generic assets like "Microsoft 365", "Azure", "Windows", "Fortinet", or "Cisco" require stronger evidence.
7. Application-level CVEs (plugins, themes, web apps) MUST NOT match generic runtimes like "PHP", "Docker", "Java", or "Nginx" unless the runtime engine itself is the vulnerable component.
8. If affected product evidence is unclear, answer UNCERTAIN.
9. If the product is clearly different, answer NOT_MATCHED.
10. If the product is clearly affected, answer MATCHED.

Return exactly this JSON structure (no other text, no markdown):
{{
  "verdict": "MATCHED | NOT_MATCHED | UNCERTAIN",
  "confidence": 0.0,
  "reason": "One clear sentence explaining the decision.",
  "recommended_action": "Short analyst recommendation."
}}
"""


async def verify_cve_asset_match(
    *,
    cve_id: str,
    title: str,
    description: str,
    affected_products: list,
    cpe_strings: list,
    vuln_type: str,
    asset_name: str,
    client_name: str,
    match_method: str,
    match_score: float,
) -> dict:
    if not settings.OPENAI_API_KEY:
        return {
            "verdict": "ERROR",
            "confidence": 0.0,
            "reason": "OPENAI_API_KEY is not configured in .env.",
            "recommended_action": "Set OPENAI_API_KEY in .env and restart the backend.",
            "error": "missing_openai_api_key",
        }

    prompt = USER_PROMPT.format(
        cve_id=cve_id,
        title=(title or "")[:500],
        description=(description or "No description available.")[:1500],
        affected_products=", ".join((affected_products or [])[:25]) or "Not specified",
        cpe_strings=", ".join((cpe_strings or [])[:25]) or "Not specified",
        vuln_type=vuln_type or "Not specified",
        asset_name=asset_name or "Unknown",
        client_name=client_name or "Unknown",
        match_method=match_method or "Unknown",
        match_score=round(float(match_score or 0), 4),
    )

    try:
        from openai import AsyncOpenAI

        client = AsyncOpenAI(api_key=settings.OPENAI_API_KEY)
        response = await client.chat.completions.create(
            model=settings.OPENAI_MODEL,
            messages=[
                {"role": "system", "content": SYSTEM_PROMPT},
                {"role": "user",   "content": prompt},
            ],
            temperature=0,
            max_tokens=300,
            response_format={"type": "json_object"},
        )

        raw  = response.choices[0].message.content
        data = json.loads(raw)

        verdict = str(data.get("verdict", "UNCERTAIN")).upper().strip()
        if verdict not in ("MATCHED", "NOT_MATCHED", "UNCERTAIN"):
            verdict = "UNCERTAIN"

        try:
            confidence = float(data.get("confidence", 0.0))
        except Exception:
            confidence = 0.0
        confidence = max(0.0, min(confidence, 1.0))

        reason             = str(data.get("reason",             "No reason provided.")).strip()
        recommended_action = str(data.get("recommended_action", "Manual analyst review required.")).strip()

        logger.info(
            "[AI Verify] %s vs %s/%s -> %s %.2f",
            cve_id, client_name, asset_name, verdict, confidence,
        )

        return {
            "verdict":            verdict,
            "confidence":         confidence,
            "reason":             reason,
            "recommended_action": recommended_action,
            "error":              None,
        }

    except Exception as e:
        logger.error("[AI Verify] OpenAI call failed: %s", e, exc_info=True)
        return {
            "verdict":            "ERROR",
            "confidence":         0.0,
            "reason":             str(e),
            "recommended_action": "Manual analyst review required.",
            "error":              str(e),
        }
