# services/reporting/pdf_renderer.py
import logging, os, re, json, subprocess, sys
from datetime import datetime
from pathlib import Path
from core.config import settings

logger = logging.getLogger(__name__)
OUTPUT_DIR = Path(settings.REPORT_OUTPUT_DIR)
OUTPUT_DIR.mkdir(exist_ok=True, parents=True)
GENERATOR_SCRIPT = Path("/app/services/reporting/docx_generator.py")

def _split_description(description):
    if not description:
        return ["No description available."]
    paras = [p.strip() for p in description.split("\n\n") if p.strip()]
    return paras if paras else [description.strip()]

async def render_pdf(report_data: dict, client_name: str, alert_number: str):
    safe_client = re.sub(r"[^a-zA-Z0-9_\-]", "_", client_name)
    safe_alert  = alert_number.replace("/", "-")
    filename    = f"{safe_alert}_{safe_client}.docx"
    filepath    = OUTPUT_DIR / filename
    report_data["description_paragraphs"] = _split_description(report_data.get("description",""))
    report_data["client_name"] = client_name
    tmp_json = f"/tmp/report_{safe_alert}_{safe_client}.json"
    with open(tmp_json, "w") as f:
        json.dump(report_data, f)
    try:
        result = subprocess.run(
            [sys.executable, str(GENERATOR_SCRIPT), tmp_json, str(filepath), client_name, alert_number],
            capture_output=True, text=True, timeout=60
        )
        if result.returncode != 0:
            logger.error(f"[DOCX] Generator error: {result.stderr[:500]}")
            raise RuntimeError(f"docx generator failed: {result.stderr[:200]}")
        size_kb = os.path.getsize(filepath) / 1024
        logger.info(f"[DOCX] Written {filename} ({size_kb:.1f} KB)")
    finally:
        if os.path.exists(tmp_json):
            os.remove(tmp_json)
    return str(filepath), filename
