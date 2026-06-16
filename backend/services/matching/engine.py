# services/matching/engine.py
"""
Improved two-layer CVE-to-client asset matching engine.

Main goals:
1. Keep high-confidence CPE matching.
2. Reduce semantic false positives.
3. Prevent confidence values above 100%.
4. Block known bad product-family matches such as:
   - FortiSandbox CVE -> FortiClient / FortiAnalyzer / FortiManager
   - FortiOS/FortiGate CVE -> FortiClient / FortiAnalyzer / FortiManager / FortiSandbox
   - SharePoint CVE -> Windows OS assets
   - Windows OS component CVE -> Microsoft 365 cloud/service assets
5. Make generic asset names harder to match semantically.

Important:
- This file remains compatible with the existing MatchResult class.
- OpenAI verification should still be handled separately as a manual second-stage analyst action.
"""

import logging
import re
from typing import List, Set, Tuple

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from core.config import settings
from models.db_models import Client, ClientAsset, CVE
from services.matching.semantic_matcher import (
    MatchResult,
    normalize_product,
    embed,
    cosine_similarity,
    cpe_matches_asset,
    embed_one,
)

logger = logging.getLogger(__name__)


# ═══════════════════════════════════════════════════════════════════════════════
# Vendor family keyword groups
# ═══════════════════════════════════════════════════════════════════════════════

VENDOR_FAMILIES = [
    {
        "cisco", "ios", "nxos", "asa", "fmc", "firepower", "meraki",
        "catalyst", "nexus", "aironet", "webex", "anyconnect", "umbrella",
    },
    {
        "microsoft", "windows", "office", "sharepoint", "exchange", "azure",
        "active directory", "iis", "hyper-v", "teams", "outlook", "365",
        "dynamics",
    },
    {
        "vmware", "esxi", "vcenter", "vsphere", "horizon", "nsx", "workstation",
    },
    {
        "fortinet", "fortigate", "fortios", "fortianalyzer", "fortimanager",
        "fortiweb", "fortimail", "forticlient", "fortisandbox",
    },
    {
        "paloalto", "palo alto", "pan-os", "globalprotect", "panorama",
        "cortex", "prisma",
    },
    {
        "checkpoint", "check point", "gaia", "smartconsole", "harmony",
    },
    {
        "juniper", "junos", "srx", "mx", "ex series",
    },
    {
        "f5", "big-ip", "bigiq", "nginx", "traffix",
    },
    {
        "linux", "ubuntu", "debian", "centos", "rhel", "red hat", "kernel",
        "openssh", "openssl", "apache", "nginx",
    },
    {
        "oracle", "java", "jdk", "weblogic", "mysql", "solaris",
    },
    {
        "sap", "hana", "netweaver", "business objects",
    },
    {
        "wordpress", "drupal", "joomla", "magento", "cms", "plugin", "theme",
        "php", "laravel", "symfony",
    },
    {
        "android", "ios", "iphone", "ipad", "mobile", "apple", "macos",
    },
    {
        "aws", "amazon", "s3", "ec2", "lambda", "cloudfront",
    },
    {
        "google", "chrome", "chromium", "android", "gcp",
    },
]


# ═══════════════════════════════════════════════════════════════════════════════
# Generic asset names
# These are allowed, but require a higher semantic threshold.
# ═══════════════════════════════════════════════════════════════════════════════

GENERIC_ASSET_TERMS = {
    "microsoft",
    "microsoft windows",
    "windows",
    "windows os",
    "microsoft 365",
    "office 365",
    "o365",
    "azure",
    "microsoft azure",
    "fortinet",
    "cisco",
    "vmware",
    "linux",
    "oracle",
    "sap",
}


# ═══════════════════════════════════════════════════════════════════════════════
# Known product-level false-positive rules
# These rules block semantic-only matching when the product is clearly different.
# If a strong CPE match exists, CPE can still match before semantic logic.
# ═══════════════════════════════════════════════════════════════════════════════

PRODUCT_EXCLUSION_RULES = [
    {
        "name": "FortiSandbox should not match other Fortinet products",
        "cve_terms": {"fortisandbox", "forti sandbox"},
        "blocked_asset_terms": {
            "forticlient",
            "forti client",
            "fortianalyzer",
            "forti analyzer",
            "fortimanager",
            "forti manager",
            "fortigate",
            "forti gate",
            "fortios",
            "forti os",
            "fortiweb",
            "forti web",
            "fortimail",
            "forti mail",
        },
        "reason": "FortiSandbox CVE should not match other Fortinet products unless explicitly affected.",
    },
    {
        "name": "FortiOS/FortiGate should not match other Fortinet products",
        "cve_terms": {"fortios", "forti os", "fortigate", "forti gate"},
        "blocked_asset_terms": {
            "forticlient",
            "forti client",
            "fortianalyzer",
            "forti analyzer",
            "fortimanager",
            "forti manager",
            "fortisandbox",
            "forti sandbox",
            "fortiweb",
            "forti web",
            "fortimail",
            "forti mail",
        },
        "reason": "FortiOS/FortiGate CVE should not match other Fortinet products unless explicitly affected.",
    },
    {
        "name": "FortiAnalyzer should not match unrelated Fortinet products",
        "cve_terms": {"fortianalyzer", "forti analyzer"},
        "blocked_asset_terms": {
            "forticlient",
            "forti client",
            "fortimanager",
            "forti manager",
            "fortisandbox",
            "forti sandbox",
            "fortigate",
            "forti gate",
            "fortios",
            "forti os",
        },
        "reason": "FortiAnalyzer CVE should not match unrelated Fortinet products unless explicitly affected.",
    },
    {
        "name": "FortiManager should not match unrelated Fortinet products",
        "cve_terms": {"fortimanager", "forti manager"},
        "blocked_asset_terms": {
            "forticlient",
            "forti client",
            "fortianalyzer",
            "forti analyzer",
            "fortisandbox",
            "forti sandbox",
            "fortigate",
            "forti gate",
            "fortios",
            "forti os",
        },
        "reason": "FortiManager CVE should not match unrelated Fortinet products unless explicitly affected.",
    },
    {
        "name": "SharePoint should not match Windows OS",
        "cve_terms": {"sharepoint", "share point"},
        "blocked_asset_terms": {
            "windows 10",
            "windows 11",
            "windows server",
            "microsoft windows",
            "win10",
            "win11",
        },
        "reason": "SharePoint CVE should not match Windows OS assets.",
    },
    {
        "name": "Windows OS component should not match Microsoft cloud services",
        "cve_terms": {
            "windows kernel",
            "kernel",
            "win32k",
            "tcp/ip",
            "tcp ip",
            "event logging",
            "event log",
            "cloud files",
            "message queuing",
            "msmq",
            "remote desktop",
            "rdp",
            "windows defender",
            "windows installer",
            "windows storage",
            "windows common log",
            "windows routing",
        },
        "blocked_asset_terms": {
            "microsoft 365",
            "office 365",
            "o365",
            "sharepoint online",
            "exchange online",
            "teams",
            "dynamics 365",
            "azure",
        },
        "reason": "Windows OS/component CVE should not match Microsoft 365, Azure, or other cloud service assets.",
    },
    {
        "name": "Dynamics 365 should not match Windows or generic Microsoft 365",
        "cve_terms": {"dynamics 365", "customer insights", "microsoft dynamics"},
        "blocked_asset_terms": {
            "windows 10",
            "windows 11",
            "windows server",
            "microsoft windows",
            "microsoft 365",
            "office 365",
            "o365",
        },
        "reason": "Dynamics 365 CVE should not match Windows OS or generic Microsoft 365 assets.",
    },
    {
        "name": "Azure service CVE should not match Windows OS",
        "cve_terms": {
            "azure monitor",
            "azure sdk",
            "azure service",
            "azure automation",
            "azure devops",
            "azure kubernetes",
        },
        "blocked_asset_terms": {
            "windows 10",
            "windows 11",
            "windows server",
            "microsoft windows",
            "microsoft 365",
            "office 365",
        },
        "reason": "Azure service CVE should not match Windows OS or generic Microsoft 365 assets.",
    },
]


# ═══════════════════════════════════════════════════════════════════════════════
# Text/token helpers
# ═══════════════════════════════════════════════════════════════════════════════

def _norm_text(value: str) -> str:
    """
    Normalise text for product rule matching.
    Keeps letters, numbers, spaces, dot, plus, slash, and hyphen-like separators.
    """
    value = (value or "").lower()
    value = value.replace("_", " ")
    value = value.replace("-", " ")
    value = value.replace("/", " ")
    value = re.sub(r"[^a-z0-9\.\+\s]", " ", value)
    return " ".join(value.split())


def _extract_tokens(text: str) -> Set[str]:
    """Extract meaningful lowercase tokens from product/vendor text."""
    text = _norm_text(text)
    tokens = set(text.split())

    stopwords = {
        "the", "a", "an", "in", "of", "for", "to", "and", "or",
        "with", "on", "at", "by", "is", "it", "as", "up", "be",
        "version", "versions", "ver", "v", "x", "n", "s",
        "through", "before", "after", "from", "using", "allows",
    }

    return {t for t in tokens if t not in stopwords and len(t) > 1}


def _contains_any(text: str, terms: Set[str]) -> bool:
    """Return True if any phrase/token in terms appears in text."""
    t = _norm_text(text)
    return any(_norm_text(term) in t for term in terms)


def _get_family_ids(tokens: Set[str]) -> Set[int]:
    """Return vendor-family IDs matched by a set of tokens."""
    token_text = " ".join(tokens)
    families = set()

    for i, family in enumerate(VENDOR_FAMILIES):
        for keyword in family:
            key = _norm_text(keyword)
            if not key:
                continue

            # Support both exact token and phrase style checks.
            if key in token_text or any(key == tok for tok in tokens):
                families.add(i)
                break

            # Support cases like "paloalto" vs "palo alto".
            compact_key = key.replace(" ", "")
            compact_text = token_text.replace(" ", "")
            if compact_key and compact_key in compact_text:
                families.add(i)
                break

    return families


def _is_generic_asset(asset_name: str) -> bool:
    """
    Generic assets should not be trusted with low semantic thresholds.
    Examples: Microsoft 365, Azure, Windows, Fortinet, Cisco.
    """
    asset = _norm_text(asset_name)
    return asset in {_norm_text(x) for x in GENERIC_ASSET_TERMS}


def _cve_combined_text(cve: CVE, cve_products: List[str]) -> str:
    """
    Build CVE text used only for rule-based blocking.
    This is not used for embeddings.
    """
    parts = [
        cve.cve_ids or "",
        cve.title or "",
        cve.description or "",
        cve.vuln_type or "",
        " ".join(cve_products or []),
    ]
    return _norm_text(" ".join(parts))


def _blocked_by_product_rule(
    cve: CVE,
    cve_products: List[str],
    asset_name: str,
) -> Tuple[bool, str]:
    """
    Block known semantic false positives.

    Important:
    - This is applied only before semantic matching.
    - CPE matching is checked first and can still confirm a true match.
    """
    cve_text = _cve_combined_text(cve, cve_products)
    asset_text = _norm_text(asset_name)

    for rule in PRODUCT_EXCLUSION_RULES:
        cve_hit = any(_norm_text(term) in cve_text for term in rule["cve_terms"])
        asset_blocked = any(
            _norm_text(term) in asset_text
            for term in rule["blocked_asset_terms"]
        )

        if cve_hit and asset_blocked:
            return True, rule["reason"]

    return False, ""


def _keyword_pre_filter(
    cve_products: List[str],
    asset_names: List[str],
) -> bool:
    """
    Coarse vendor-family filter.

    Returns:
        True  -> proceed to semantic matching
        False -> skip client entirely

    Logic:
    - If CVE products have no known vendor family, proceed.
    - If client assets have no known vendor family, proceed.
    - If both have known families and there is no overlap, skip.
    """
    if not cve_products:
        return True

    cve_tokens: Set[str] = set()
    for product in cve_products:
        cve_tokens.update(_extract_tokens(product))

    cve_families = _get_family_ids(cve_tokens)

    if not cve_families:
        return True

    asset_tokens: Set[str] = set()
    for asset_name in asset_names:
        asset_tokens.update(_extract_tokens(asset_name))

    asset_families = _get_family_ids(asset_tokens)

    if not asset_families:
        return True

    return bool(cve_families & asset_families)


def _keyword_boost(
    cve_products: List[str],
    asset_name: str,
) -> float:
    """
    Small boost for direct product-token overlap.

    The final score is capped to 1.0 later.
    """
    asset_tokens = _extract_tokens(asset_name)
    boost = 0.0

    for product in cve_products:
        product_tokens = _extract_tokens(product)
        product_tokens = {t for t in product_tokens if len(t) > 3}

        overlap = product_tokens & asset_tokens

        if overlap:
            boost = min(0.15, len(overlap) * 0.05)
            break

    return boost


def _required_semantic_threshold(asset_name: str, base_threshold: float) -> float:
    """
    Apply stricter threshold for generic asset names.
    """
    if _is_generic_asset(asset_name):
        return max(base_threshold, 0.90)

    return base_threshold


def _safe_score(score: float) -> float:
    """Ensure score is always between 0.0 and 1.0."""
    try:
        return round(max(0.0, min(float(score), 1.0)), 4)
    except Exception:
        return 0.0


def _dedupe_keep_order(items: List[str]) -> List[str]:
    """Remove duplicates while keeping original order."""
    seen = set()
    output = []

    for item in items:
        key = _norm_text(item)
        if not key or key in seen:
            continue
        seen.add(key)
        output.append(item)

    return output


# ═══════════════════════════════════════════════════════════════════════════════
# Main matching function
# ═══════════════════════════════════════════════════════════════════════════════

async def match_cve_to_clients(
    cve: CVE,
    db: AsyncSession,
) -> List[MatchResult]:
    """
    Run CPE and semantic matching against all clients.

    Matching order:
    1. Client-level vendor family pre-filter.
    2. Per-asset CPE matching.
    3. Per-asset product exclusion rules.
    4. Semantic similarity against affected_products only.
    5. Score cap at 1.0.

    Returns:
        List[MatchResult]
    """
    threshold = settings.SEMANTIC_MATCH_THRESHOLD

    result = await db.execute(
        select(Client).where(Client.assets.any())
    )
    clients: List[Client] = result.scalars().unique().all()

    if not clients:
        return []

    cve_products: List[str] = cve.affected_products or []
    cve_cpes: List[str] = cve.cpe_strings or []

    # Do not embed CVE title. It causes generic false positives.
    # Only embed structured affected product names.
    product_texts = [
        normalize_product(product)
        for product in cve_products
        if product and product.strip()
    ]

    cve_embeddings = embed(product_texts) if product_texts else None

    results: List[MatchResult] = []

    for client in clients:
        assets: List[ClientAsset] = client.assets or []
        if not assets:
            continue

        asset_names = [asset.asset_name for asset in assets if asset.asset_name]

        # Client-level coarse pre-filter.
        if cve_products and not _keyword_pre_filter(cve_products, asset_names):
            logger.debug(
                "[Match] CVE %s -> client %s skipped due to vendor-family mismatch",
                cve.cve_ids,
                client.name,
            )
            continue

        matched_assets: List[str] = []
        matched_cpes: List[str] = []
        best_score = 0.0
        method_used = ""

        for asset in assets:
            asset_name = asset.asset_name or ""
            if not asset_name.strip():
                continue

            asset_matched = False
            asset_best_score = 0.0
            asset_method = ""

            # ── Layer 1: CPE matching ────────────────────────────────────────
            # CPE match is evaluated before product-exclusion rules.
            # If CPE explicitly confirms the product, allow it.
            for cpe in cve_cpes:
                matched, conf = cpe_matches_asset(
                    cpe,
                    asset_name,
                    asset.cpe_string,
                )

                if matched and conf > asset_best_score:
                    asset_matched = True
                    asset_best_score = _safe_score(conf)
                    asset_method = "cpe"

                    if cpe not in matched_cpes:
                        matched_cpes.append(cpe)

            # ── Layer 2: Semantic matching ───────────────────────────────────
            # Only run semantic logic if no CPE match already confirmed this asset.
            if cve_embeddings is not None and asset_method != "cpe":
                blocked, block_reason = _blocked_by_product_rule(
                    cve,
                    cve_products,
                    asset_name,
                )

                if blocked:
                    logger.debug(
                        "[Match] Blocked semantic false positive: CVE=%s asset='%s' client='%s' reason=%s",
                        cve.cve_ids,
                        asset_name,
                        client.name,
                        block_reason,
                    )
                    continue

                asset_embedding = (
                    asset.embedding
                    if asset.embedding is not None
                    else embed_one(normalize_product(asset_name))
                )

                required_threshold = _required_semantic_threshold(
                    asset_name,
                    threshold,
                )

                for cve_embedding in cve_embeddings:
                    sim = cosine_similarity(cve_embedding, asset_embedding)
                    boost = _keyword_boost(cve_products, asset_name)
                    effective_score = _safe_score(sim + boost)

                    # Must meet threshold before boost to avoid boost-driven false positives.
                    if sim >= required_threshold and effective_score > asset_best_score:
                        asset_matched = True
                        asset_best_score = effective_score
                        asset_method = "semantic"

            if asset_matched:
                matched_assets.append(asset_name)

                if asset_best_score > best_score:
                    best_score = asset_best_score
                    method_used = asset_method

        matched_assets = _dedupe_keep_order(matched_assets)
        matched_cpes = _dedupe_keep_order(matched_cpes)

        if matched_assets:
            final_score = _safe_score(best_score)

            # Hard floor: never emit a match below the configured threshold.
            # CPE exact matches (1.0) and qualifying semantic matches pass;
            # vendor-only / weak matches are dropped here regardless of path.
            MIN_ALERT_SCORE = max(0.80, float(settings.SEMANTIC_MATCH_THRESHOLD) - 0.15)
            if final_score < MIN_ALERT_SCORE:
                logger.info(
                    "[Match] CVE %s -> client=%s DROPPED (score=%.3f < floor=%.2f)",
                    cve.cve_ids, client.name, final_score, MIN_ALERT_SCORE,
                )
                continue

            results.append(
                MatchResult(
                    client_id=client.id,
                    client_name=client.name,
                    matched_assets=matched_assets,
                    matched_cpes=matched_cpes,
                    method=method_used,
                    score=final_score,
                )
            )

            logger.info(
                "[Match] CVE %s -> client=%s assets=%d method=%s score=%.3f threshold=%.2f",
                cve.cve_ids,
                client.name,
                len(matched_assets),
                method_used,
                final_score,
                threshold,
            )

    return results


# ═══════════════════════════════════════════════════════════════════════════════
# Asset embedding helpers
# ═══════════════════════════════════════════════════════════════════════════════

async def embed_and_store_asset(asset: ClientAsset, db: AsyncSession) -> None:
    """Compute and persist embedding for a single asset."""
    text = normalize_product(asset.asset_name)
    embedding = embed_one(text)

    asset.embedding = embedding
    db.add(asset)
    await db.commit()

    logger.debug("Embedded asset: %s", asset.asset_name)


async def embed_all_assets(db: AsyncSession) -> int:
    """Batch embed all assets that do not have embeddings yet."""
    result = await db.execute(
        select(ClientAsset).where(ClientAsset.embedding.is_(None))
    )
    assets = result.scalars().all()

    if not assets:
        return 0

    texts = [normalize_product(asset.asset_name) for asset in assets]
    embeddings = embed(texts)

    for asset, embedding in zip(assets, embeddings):
        asset.embedding = embedding.tolist()
        db.add(asset)

    await db.commit()

    logger.info("Embedded %d assets", len(assets))
    return len(assets)


# ═══════════════════════════════════════════════════════════════════════════════
# Rematch helper
# ═══════════════════════════════════════════════════════════════════════════════

async def rematch_all_cves(db: AsyncSession) -> dict:
    """
    Re-run matching for all existing HIGH/CRITICAL CVEs.

    Existing CVEs that already have alerts are skipped to avoid duplicate alerts.
    """
    from sqlalchemy import func
    from models.db_models import Alert

    cves_result = await db.execute(
        select(CVE)
        .where(CVE.severity.in_(["CRITICAL", "HIGH"]))
        .order_by(
            CVE.priority_score.desc().nullslast(),
            CVE.date_added.desc(),
        )
    )
    cves = cves_result.scalars().all()

    total_alerts = 0
    cves_matched = 0

    for cve in cves:
        existing_count = await db.scalar(
            select(func.count(Alert.id)).where(Alert.cve_id == cve.id)
        )

        if existing_count:
            continue

        matches = await match_cve_to_clients(cve, db)

        for match in matches:
            safe_score = _safe_score(match.score)

            alert = Alert(
                cve_id=cve.id,
                client_id=match.client_id,
                match_method=match.method,
                match_score=safe_score,
                matched_assets=match.matched_assets,
                matched_cpes=match.matched_cpes,
            )

            # These attributes exist only after you add the new DB fields.
            # setattr keeps this file safer if the DB model is not updated yet.
            for field_name, field_value in {
                "raw_match_score": safe_score,
                "boosted_match_score": safe_score,
                "match_decision": "confirmed_match" if match.method == "cpe" else "needs_review",
                "match_reason": (
                    "CPE/product match found."
                    if match.method == "cpe"
                    else "Semantic product similarity matched. Analyst review recommended."
                ),
            }.items():
                if hasattr(alert, field_name):
                    setattr(alert, field_name, field_value)

            db.add(alert)
            total_alerts += 1

        if matches:
            cves_matched += 1
            await db.commit()

    logger.info(
        "[Rematch] Done — %d CVEs processed, %d CVEs matched, %d alerts created",
        len(cves),
        cves_matched,
        total_alerts,
    )

    return {
        "cves_processed": len(cves),
        "cves_matched": cves_matched,
        "alerts_created": total_alerts,
    }
