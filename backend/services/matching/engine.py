# services/matching/engine.py
"""
Two-layer matching engine:

Layer 1 — CPE Exact Match
  Uses NVD's structured CPE 2.3 strings to find exact vendor:product matches
  against client asset CPE strings. Highest precision.

Layer 2 — Semantic Similarity
  Embeds CVE affected product descriptions + asset names using all-MiniLM-L6-v2.
  Cosine similarity ≥ threshold triggers a match. Catches informal names,
  abbreviations, and paraphrased product names.

Both layers run for every CVE. Results are merged with deduplication.
Layer 1 matches get score 0.9–1.0, Layer 2 gets the raw cosine score.
"""
import logging
from typing import List, Optional
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select

from models.db_models import Client, ClientAsset, CVE
from services.matching.semantic_matcher import (
    MatchResult, normalize_product, embed, cosine_similarity,
    cpe_matches_asset, embed_one
)
from core.config import settings

logger = logging.getLogger(__name__)

THRESHOLD = settings.SEMANTIC_MATCH_THRESHOLD


async def match_cve_to_clients(
    cve: CVE,
    db: AsyncSession,
) -> List[MatchResult]:
    """
    Run both matching layers against all clients in the database.
    Returns a list of MatchResult objects for clients with at least one asset match.
    """
    # Load all clients with their assets
    result = await db.execute(
        select(Client).where(Client.assets.any())
    )
    clients: List[Client] = result.scalars().unique().all()

    if not clients:
        return []

    cve_products: List[str] = cve.affected_products or []
    cve_cpes: List[str] = cve.cpe_strings or []

    # Build embeddings for CVE products (batch)
    product_texts = [normalize_product(p) for p in cve_products]
    # Include title keywords
    product_texts.append(normalize_product(cve.title))

    cve_embeddings = embed(product_texts) if product_texts else None

    results: List[MatchResult] = []

    for client in clients:
        assets: List[ClientAsset] = client.assets
        if not assets:
            continue

        matched_assets: List[str] = []
        matched_cpes: List[str] = []
        best_score: float = 0.0
        method_used: str = ""

        for asset in assets:
            asset_matched = False
            asset_best_score = 0.0
            asset_method = ""

            # ── Layer 1: CPE exact match ──────────────────────────────────────
            for cpe in cve_cpes:
                matched, conf = cpe_matches_asset(cpe, asset.asset_name, asset.cpe_string)
                if matched and conf > asset_best_score:
                    asset_matched = True
                    asset_best_score = conf
                    asset_method = "cpe"
                    if cpe not in matched_cpes:
                        matched_cpes.append(cpe)

            # ── Layer 2: Semantic similarity ──────────────────────────────────
            if cve_embeddings is not None:
                # Use stored embedding if available, else compute on the fly
                if asset.embedding is not None:
                    asset_emb = asset.embedding
                else:
                    asset_emb = embed_one(normalize_product(asset.asset_name))

                for cve_emb in cve_embeddings:
                    sim = cosine_similarity(cve_emb, asset_emb)
                    if sim >= THRESHOLD and sim > asset_best_score:
                        asset_matched = True
                        asset_best_score = sim
                        asset_method = "semantic" if asset_method != "cpe" else "both"

            if asset_matched:
                matched_assets.append(asset.asset_name)
                if asset_best_score > best_score:
                    best_score = asset_best_score
                    method_used = asset_method

        if matched_assets:
            results.append(MatchResult(
                client_id=client.id,
                client_name=client.name,
                matched_assets=matched_assets,
                matched_cpes=matched_cpes,
                method=method_used,
                score=round(best_score, 4),
            ))
            logger.info(
                f"[Match] CVE {cve.cve_ids} → {client.name} "
                f"({len(matched_assets)} assets, method={method_used}, score={best_score:.3f})"
            )

    return results


async def embed_and_store_asset(asset: ClientAsset, db: AsyncSession) -> None:
    """Compute and persist embedding for a single asset."""
    text = normalize_product(asset.asset_name)
    embedding = embed_one(text)
    asset.embedding = embedding
    db.add(asset)
    await db.commit()
    logger.debug(f"Embedded asset: {asset.asset_name}")


async def embed_all_assets(db: AsyncSession) -> int:
    """Batch embed all assets that don't have embeddings yet."""
    result = await db.execute(
        select(ClientAsset).where(ClientAsset.embedding.is_(None))
    )
    assets = result.scalars().all()

    if not assets:
        return 0

    texts = [normalize_product(a.asset_name) for a in assets]
    embeddings = embed(texts)

    for asset, emb in zip(assets, embeddings):
        asset.embedding = emb.tolist()
        db.add(asset)

    await db.commit()
    logger.info(f"Embedded {len(assets)} assets")
    return len(assets)
