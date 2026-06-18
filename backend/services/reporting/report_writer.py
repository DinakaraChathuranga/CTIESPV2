# services/reporting/report_writer.py
# Primary LLM: OpenAI API (gpt-4o or configured model)
# Fallback: free Gemini API
import json, logging, os, re, asyncio
from datetime import datetime
import httpx
from core.config import settings
from models.db_models import CVE, Client, Alert
from services.reporting.rag_store import query_similar_reports

logger = logging.getLogger(__name__)

SYSTEM_PROMPT = """You are a senior cybersecurity analyst at an MSSP writing professional CTI security advisories. Write in professional British English. Return ONLY valid JSON with no markdown fences or explanation."""

OUTPUT_SCHEMA = """{
  "title": "Full descriptive vulnerability title",
  "type": "e.g. Remote Code Execution, Authentication Bypass, Privilege Escalation",
  "severity": "CRITICAL or HIGH or MEDIUM or LOW",
  "cvss_score": "numeric score as string e.g. 9.8",
  "epss_note": "One sentence on exploit probability from EPSS data",
  "target_platforms": "Comma-separated list of affected platforms",
  "overview_table": [{"product": "Product Name", "severity": "CRITICAL", "cve_id": "CVE-XXXX-XXXXX"}],
  "description": "Write 3-4 full professional paragraphs. Paragraph 1: what the vulnerability is and its technical cause. Paragraph 2: how it is exploited and by whom. Paragraph 3: what the business and security impact is. Paragraph 4: urgency and context. NO bullet points in description.",
  "affected_products": ["Product 1", "Product 2"],
  "affected_versions": "Specific version ranges e.g. versions 2.483 through 2.550",
  "severity_detail": "e.g. CRITICAL (CVSS 9.8)",
  "impact": ["Impact Title - Detailed explanation of this specific impact point", "Impact Title 2 - Explanation", "Impact Title 3 - Explanation", "Impact Title 4 - Explanation", "Impact Title 5 - Explanation"],
  "attack_vector": "e.g. Remote (Unauthenticated) / Network-based",
  "remediation": "Write 3-4 sentences with specific actionable steps including exact patch versions where known. Include interim mitigations if immediate patching is not possible.",
  "references": ["https://...", "https://..."],
  "client_note": "2 sentences directly addressing this specific client about their affected assets and what they must do immediately.",
  "disclaimer": "The information provided here is on an as-is basis, without warranty of any kind. Products past End of General Support are not evaluated."
}"""


def _build_prompt(cve, client, alert, rag_examples=None):
    products = ", ".join(cve.affected_products or [])
    matched = ", ".join(alert.matched_assets or [a.asset_name for a in (client.assets or [])][:3] or [])
    epss = f"{cve.epss_score:.1%}" if cve.epss_score else "N/A"
    kev_note = "YES — actively exploited in the wild per CISA KEV" if cve.is_kev else "No"
    refs = "\n".join((cve.refs or [])[:5])

    rag_section = ""
    if rag_examples:
        rag_section = "\n\nSTYLE REFERENCE EXAMPLES — match this advisory writing style and structure:\n"
        for i, ex in enumerate(rag_examples[:3], 1):
            meta = ex.get("meta", {})
            text = (ex.get("text") or "")[:1500]
            rag_section += f"\n--- Example {i} ({meta.get('filename', 'sample')}) ---\n{text}\n"

    return f"""Generate a professional CTI security advisory for client: {client.name}

CVE INTELLIGENCE:
- CVE ID(s): {cve.cve_ids}
- Title: {cve.title}
- Severity: {cve.severity} (CVSS {cve.cvss_score or 'N/A'})
- EPSS Score: {epss} exploit probability
- CISA KEV Status: {kev_note}
- Vulnerability Type: {cve.vuln_type or 'Security Vulnerability'}
- Affected Products: {products}
- Attack Vector: {cve.attack_vector or 'Network'}
- Attack Complexity: {cve.attack_complexity or 'Low'}
- Privileges Required: {cve.privileges_required or 'None'}
- Description: {cve.description or 'See NVD database for full details'}
- Known Impact: {', '.join(cve.impact or [])}
- Remediation: {cve.remediation or 'Apply vendor patches immediately'}
- References:
{refs}

CLIENT CONTEXT:
- Client Name: {client.name}
- Contact: {client.email}
- Affected Assets in Their Environment: {matched or 'See asset registry'}

Write a comprehensive, professional advisory. The description must be 3-4 full paragraphs of professional prose. Impact must be 5 specific detailed points in format "Title - Description". Remediation must include specific patch versions and interim mitigations.
{rag_section}
Return this exact JSON schema:
{OUTPUT_SCHEMA}"""


async def _call_openai(prompt: str) -> str:
    """Primary LLM: OpenAI API."""
    from openai import AsyncOpenAI
    api_key = settings.OPENAI_API_KEY
    if not api_key:
        raise RuntimeError("OPENAI_API_KEY not set")
    model = settings.OPENAI_MODEL
    client = AsyncOpenAI(api_key=api_key)
    response = await client.chat.completions.create(
        model=model,
        messages=[
            {"role": "system", "content": SYSTEM_PROMPT},
            {"role": "user", "content": prompt},
        ],
        temperature=0.3,
        max_tokens=1500,
        response_format={"type": "json_object"},
    )
    return response.choices[0].message.content


async def _call_gemini_free(prompt: str) -> str:
    """Fallback: free Gemini API with retry on 429."""
    api_key = settings.GEMINI_API_KEY if hasattr(settings, 'GEMINI_API_KEY') else ""
    if not api_key:
        raise RuntimeError("GEMINI_API_KEY not set")
    url = f"https://generativelanguage.googleapis.com/v1beta/models/gemini-2.0-flash:generateContent?key={api_key}"
    payload = {
        "contents": [{"parts": [{"text": SYSTEM_PROMPT + "\n\n" + prompt}]}],
        "generationConfig": {"temperature": 0.3, "maxOutputTokens": 4096}
    }
    for attempt in range(5):
        try:
            async with httpx.AsyncClient(timeout=90.0) as client:
                resp = await client.post(url, json=payload)
                if resp.status_code == 429:
                    wait = (attempt + 1) * 20
                    logger.warning(f"[ReportWriter] Gemini 429 — retrying in {wait}s (attempt {attempt+1}/5)")
                    await asyncio.sleep(wait)
                    continue
                resp.raise_for_status()
                data = resp.json()
                return data["candidates"][0]["content"]["parts"][0]["text"]
        except Exception as e:
            if "429" in str(e) and attempt < 4:
                await asyncio.sleep((attempt + 1) * 20)
            elif attempt == 4:
                raise
    raise RuntimeError("Gemini free API failed after 5 attempts")


def _parse_response(raw: str) -> dict:
    cleaned = re.sub(r"```(?:json)?", "", raw).strip()
    start = cleaned.find("{")
    end = cleaned.rfind("}") + 1
    if start == -1:
        raise ValueError("No JSON found in response")
    return json.loads(cleaned[start:end])


def _fallback_report(cve, client, alert):
    matched = ", ".join(alert.matched_assets or [])
    return {
        "title": cve.title,
        "type": cve.vuln_type or "Security Vulnerability",
        "severity": cve.severity,
        "cvss_score": str(cve.cvss_score or "N/A"),
        "epss_note": f"{cve.epss_score:.1%} probability of exploitation" if cve.epss_score else "EPSS data unavailable",
        "target_platforms": ", ".join(cve.affected_products or []),
        "overview_table": [{"product": p, "severity": cve.severity, "cve_id": cve.cve_ids}
                           for p in (cve.affected_products or ["Affected Product"])[:3]],
        "description": cve.description or "Vulnerability details not available. Refer to the CVE database.",
        "affected_products": cve.affected_products or [],
        "affected_versions": "Refer to vendor advisory for specific version ranges.",
        "severity_detail": f"{cve.severity} (CVSS {cve.cvss_score or 'N/A'})",
        "impact": cve.impact or [
            "Remote Code Execution - Exploitation could allow attackers to run system-level commands on the affected host",
            "Authentication Bypass - Attackers may bypass authentication mechanisms to gain unauthorised access",
            "Privilege Escalation - Low-privileged users may escalate to administrative level on the affected system",
            "Data Exposure - Sensitive configuration files or credentials could be accessed or exfiltrated",
            "Operational Disruption - Attackers may disable security monitoring or interfere with business operations"
        ],
        "attack_vector": cve.attack_vector or "Network (Unauthenticated)",
        "remediation": cve.remediation or "Apply the latest security patches from the vendor immediately. Restrict network access to affected services as an interim measure where patching cannot be applied immediately.",
        "references": cve.refs or [],
        "client_note": f"This vulnerability directly affects your environment ({matched}). Immediate patching is required as a priority action.",
        "disclaimer": "The information provided here is on an as-is basis, without warranty of any kind. Products past End of General Support are not evaluated.",
    }


def _make_alert_number():
    import uuid
    now = datetime.utcnow()
    return f"MITESP{now.strftime('%y%m')}-{str(uuid.uuid4())[:6].upper()}"


async def generate_report_data(cve: CVE, client: Client, alert: Alert):
    rag_examples = await query_similar_reports(
        query_text=f"{cve.severity} {cve.vuln_type or ''} {cve.title[:100]}",
        severity=cve.severity,
        n_results=settings.RAG_NUM_EXAMPLES,
    )
    rag_filenames = list({ex["meta"].get("filename", "") for ex in rag_examples})

    prompt = _build_prompt(cve, client, alert, rag_examples=rag_examples)
    report_data = None

    # Primary: OpenAI API
    try:
        raw = await _call_openai(prompt)
        report_data = _parse_response(raw)
        logger.info(f"[ReportWriter] OpenAI generated report for {cve.cve_ids} → {client.name}")
    except Exception as e:
        logger.warning(f"[ReportWriter] OpenAI unavailable: {e} — trying Gemini fallback")

    # Fallback: free Gemini API
    if report_data is None:
        try:
            raw = await _call_gemini_free(prompt)
            report_data = _parse_response(raw)
            logger.info(f"[ReportWriter] Gemini generated report for {cve.cve_ids} → {client.name}")
        except Exception as e:
            logger.error(f"[ReportWriter] All AI providers failed: {e} — using structured fallback")
            report_data = _fallback_report(cve, client, alert)

    report_data["alert_number"] = _make_alert_number()
    report_data["generated_at"] = datetime.utcnow().isoformat()
    report_data["client_name"] = client.name
    report_data["cve_ids"] = cve.cve_ids
    report_data["is_kev"] = cve.is_kev
    report_data["rag_examples_used"] = rag_filenames
    return report_data, rag_filenames
