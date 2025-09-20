import os
from typing import List, Optional, Dict, Any

from fastapi import FastAPI, HTTPException, Body
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse
from pydantic import BaseModel, Field
from dotenv import load_dotenv; load_dotenv()

from services.github_client import GitHubClient
from services.review_agent import ReviewEngine, ReviewFinding, ReviewResult


class ReviewRequest(BaseModel):
    repo_owner: str = Field(..., description="GitHub org/user")
    repo_name: str = Field(..., description="GitHub repository name")
    pr_number: int = Field(..., description="Pull Request number")
    inline: bool = Field(default=True, description="Return inline comments list")
    natural_language: bool = Field(
        default=False,
        description="If true, returns conversational/plain-English summary as well",
    )
    query: Optional[str] = Field(
        default=None,
        description="If contains 'explain issues in plain English', NL mode is enabled",
    )


app = FastAPI(title="PR Review Agent", version="1.1.0")


# Root serves UI
@app.get("/")
async def root_page():
    return FileResponse("frontend/index.html")


# Optional static assets
app.mount("/static", StaticFiles(directory="frontend"), name="static")


@app.get("/healthz")
async def healthz():
    return {"status": "ok"}


@app.post("/review", response_model=Dict[str, Any])
async def review_endpoint(payload: ReviewRequest = Body(...)) -> Dict[str, Any]:
    """Review a GitHub PR by number and return structured feedback."""
    natural_lang = payload.natural_language or (
        isinstance(payload.query, str)
        and "explain issues in plain english" in payload.query.lower()
    )

    github_token = os.getenv("GITHUB_TOKEN")
    client = GitHubClient(token=github_token)

    try:
        files = await client.fetch_pr_files(
            owner=payload.repo_owner, repo=payload.repo_name, pr_number=payload.pr_number
        )
    except Exception as e:
        raise HTTPException(status_code=502, detail=f"GitHub API error: {e}")

    if not files:
        return {
            "summary": "No changed files found in this PR.",
            "score": 100,
            "comments": [],
            "inline_comments": [],
        }

    engine = ReviewEngine()
    all_findings: List[ReviewFinding] = []

    for f in files:
        filename: str = f.get("filename", "")
        patch: Optional[str] = f.get("patch")
        if not patch:
            all_findings.append(
                ReviewFinding(
                    file=filename,
                    line=None,
                    feedback="File changed but no textual patch available (binary/large file). Consider manual review.",
                    severity="info",
                    rule="no-text-diff",
                )
            )
            continue

        findings = engine.generate_feedback(diff_text=patch, file=filename)
        all_findings.extend(findings)

    result: ReviewResult = engine.summarize_and_score(all_findings)

    response: Dict[str, Any] = {
        "summary": result.summary_natural if natural_lang else result.summary,
        "score": result.score,
        "comments": [
            {"file": f.file, "line": f.line, "feedback": f.feedback}
            for f in all_findings
        ],
        "inline_comments": [
            {"path": f.file, "side": "RIGHT", "line": f.line, "body": f.feedback}
            for f in all_findings
            if f.line is not None
        ],
    }
    return response
