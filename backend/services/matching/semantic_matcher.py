# services/matching/semantic_matcher.py
"""
Two-layer asset matching engine:
  Layer 1 — CPE exact matching (high precision)
  Layer 2 — Semantic similarity via all-mpnet-base-v2 (pgvector)

all-mpnet-base-v2 was chosen because:
  - 768-dimensional embeddings (vs 384 for MiniLM) — richer representation
  - Strong understanding of technical English terminology
  - CPU-optimised, ~420MB, no GPU required
  - Significantly better than all-MiniLM-L6-v2 for technical product names
    e.g. correctly relates "MS Exchange", "OWA", "ProxyShell"
  - Pre-downloaded in Docker image — no cold start
"""
import logging
import re
from typing import List, Optional, Tuple

import numpy as np
from sentence_transformers import SentenceTransformer

from core.config import settings

logger = logging.getLogger(__name__)

# Singleton — loaded once at startup
_model: Optional[SentenceTransformer] = None


def get_model() -> SentenceTransformer:
    global _model
    if _model is None:
        logger.info(f"Loading embedding model: {settings.EMBEDDING_MODEL}")
        _model = SentenceTransformer(settings.EMBEDDING_MODEL)
        logger.info(f"Embedding model loaded — dim={_model.get_sentence_embedding_dimension()}")
    return _model


def embed(texts: List[str]) -> np.ndarray:
    """Return L2-normalised embeddings (for cosine similarity via dot product)."""
    model = get_model()
    return model.encode(texts, normalize_embeddings=True, show_progress_bar=False)


def embed_one(text: str) -> List[float]:
    return embed([text])[0].tolist()


def cosine_similarity(a: List[float], b: List[float]) -> float:
    """Cosine similarity between two pre-normalized vectors."""
    a_arr = np.array(a, dtype=np.float32)
    b_arr = np.array(b, dtype=np.float32)
    return float(np.dot(a_arr, b_arr))


# ─── Normalization helpers ─────────────────────────────────────────────────────

_REMOVE = re.compile(r"[^a-z0-9\s\-\.]")
_ABBREVS = {
    "fmc": "firewall management center",
    "scc": "security cloud control",
    "asa": "adaptive security appliance",
    "ios": "internetwork operating system",
    "nxos": "nexus operating system",
    "esxi": "esxi hypervisor",
    "vcenter": "vcenter server",
    "owa": "outlook web access exchange",
    "ids": "intrusion detection system",
    "ips": "intrusion prevention system",
    "waf": "web application firewall",
    "vpn": "virtual private network",
    "ssl": "secure sockets layer",
    "tls": "transport layer security",
    "rdp": "remote desktop protocol",
    "smb": "server message block",
    "ad": "active directory",
    "dc": "domain controller",
    "fw": "firewall",
    "mgmt": "management",
    "srv": "server",
    "svr": "server",
    "db": "database",
    "app": "application",
    "ver": "version",
    "vm": "virtual machine",
    "mfa": "multi factor authentication",
    "sso": "single sign on",
    "edr": "endpoint detection response",
    "siem": "security information event management",
    "soar": "security orchestration automation response",
    "xdr": "extended detection response",
}


def normalize_product(name: str) -> str:
    """Normalize a product name for embedding — expand abbreviations, lowercase, clean."""
    s = name.lower().strip()
    s = _REMOVE.sub(" ", s)
    tokens = s.split()
    expanded = [_ABBREVS.get(tok, tok) for tok in tokens]
    s = " ".join(expanded)
    # Remove version numbers
    s = re.sub(r"\b\d+[\.\d]*\b", "", s)
    return " ".join(s.split())


# ─── CPE-based matching ───────────────────────────────────────────────────────

def parse_cpe(cpe: str) -> dict:
    """Parse CPE 2.3 string: cpe:2.3:a:vendor:product:version:..."""
    parts = cpe.split(":")
    if len(parts) < 6:
        return {}
    return {
        "type":    parts[2],
        "vendor":  parts[3].replace("_", " "),
        "product": parts[4].replace("_", " "),
        "version": parts[5] if len(parts) > 5 else "*",
    }


def cpe_matches_asset(cpe: str, asset_name: str, asset_cpe: Optional[str] = None) -> Tuple[bool, float]:
    """Check if a CVE CPE matches an asset. Returns (matched, confidence_score)."""
    if asset_cpe:
        cpe_parts = cpe.lower().split(":")
        asset_parts = asset_cpe.lower().split(":")
        if len(cpe_parts) >= 5 and len(asset_parts) >= 5:
            if cpe_parts[3] == asset_parts[3] and cpe_parts[4] == asset_parts[4]:
                return True, 1.0

    parsed = parse_cpe(cpe)
    if not parsed:
        return False, 0.0

    asset_lower = asset_name.lower()
    vendor = parsed.get("vendor", "")
    product = parsed.get("product", "")

    vendor_hit = vendor and vendor in asset_lower
    product_hit = product and product in asset_lower

    if vendor_hit and product_hit:
        return True, 0.95
    if product_hit and len(product) > 4:
        return True, 0.8
    if vendor_hit and len(vendor) > 3:
        return True, 0.5

    return False, 0.0


# ─── Match result ─────────────────────────────────────────────────────────────

class MatchResult:
    def __init__(
        self,
        client_id: str,
        client_name: str,
        matched_assets: List[str],
        matched_cpes: List[str],
        method: str,
        score: float,
    ):
        self.client_id = client_id
        self.client_name = client_name
        self.matched_assets = matched_assets
        self.matched_cpes = matched_cpes
        self.method = method
        self.score = score

    def to_dict(self) -> dict:
        return {
            "client_id": self.client_id,
            "client_name": self.client_name,
            "matched_assets": self.matched_assets,
            "matched_cpes": self.matched_cpes,
            "method": self.method,
            "score": self.score,
        }
