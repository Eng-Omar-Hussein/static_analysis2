import hashlib

import validators
from fastapi import APIRouter, HTTPException
from pydantic import BaseModel, field_validator

from db import SessionLocal
from model import URLAnalysisResult
from url_scoring import compute_url_score
from utils import fetch_url_content

router = APIRouter()


class URLRequest(BaseModel):
    """Request body for the /analyze-url endpoint."""

    url: str

    @field_validator("url")
    @classmethod
    def validate_url(cls, v: str) -> str:
        v = v.strip()
        if not v:
            raise ValueError("URL must not be empty")
        # Ensure scheme is present
        if not v.startswith(("http://", "https://")):
            v = "http://" + v
        if not validators.url(v):
            raise ValueError(f"Invalid URL: {v}")
        return v


@router.post("/analyze-url")
async def analyze_url(body: URLRequest):
    """
    Perform multi-layer static and content-based analysis of a URL.

    Analysis pipeline:
      1. URL structure analysis (length, chars, TLD, homograph ...)
      2. Domain intelligence (WHOIS age, DNS records)
      3. Content analysis (HTML iframes, obfuscated JS, phishing forms ...)
      4. Threat intelligence (VirusTotal URL + domain lookup)
      5. Risk scoring engine (weighted aggregation)
      6. Explainable verdict generation

    Returns:
      - score   : integer risk score
      - verdict : SAFE | SUSPICIOUS | MALICIOUS
      - reasons : list of triggered indicators
    """
    url = body.url
    url_hash = hashlib.sha256(url.encode()).hexdigest()

    db = SessionLocal()
    try:
        cached = db.query(URLAnalysisResult).filter_by(url_hash=url_hash).first()
        if cached:
            return {
                "message": "URL already analyzed",
                "url": cached.url,
                "domain": cached.domain,
                "score": cached.score,
                "verdict": cached.verdict,
                "reasons": cached.reasons,
                "final_url": cached.final_url,
                "http_status": cached.http_status,
                "redirect_count": cached.redirect_count,
            }

        # Fetch page content asynchronously (with timeout)
        content = await fetch_url_content(url, timeout=5.0)

        # Run the scoring engine
        result = compute_url_score(
            url=url,
            html_body=content.get("body", ""),
            redirect_count=content.get("redirect_count", 0),
            fetch_error=content.get("error"),
        )

        # Attach fetch metadata for transparency
        final_url = content.get("final_url", url)
        http_status = content.get("status_code")
        redirect_count = content.get("redirect_count", 0)

        result["final_url"] = final_url
        result["http_status"] = http_status
        result["redirect_count"] = redirect_count

        db_entry = URLAnalysisResult(
            url_hash=url_hash,
            url=result["url"],
            domain=result["domain"],
            score=result["score"],
            verdict=result["verdict"],
            reasons=result["reasons"],
            final_url=final_url,
            http_status=http_status,
            redirect_count=redirect_count,
        )
        db.add(db_entry)
        db.commit()

        return result

    except Exception as exc:
        raise HTTPException(
            status_code=500,
            detail=f"Analysis failed: {str(exc)}",
        )
    finally:
        db.close()
