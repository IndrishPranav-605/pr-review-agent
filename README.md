# PR Review Agent (FastAPI + GitHub) – CodeMate Hackathon


A modular PR Review Agent that analyzes GitHub pull requests via heuristics and returns a structured summary, score (0–100), and inline-style comments. Built for extensibility with CodeMate Extension AI.


## ✨ Features
- **Endpoint**: `POST /review` with `{ repo_owner, repo_name, pr_number }`.
- **GitHub Integration**: Reads changed files and unified diffs via REST API.
- **Heuristics**: Detects missing docstrings, complexity, security smells, secrets, and style issues.
- **Scoring (0–100)**: Weights issues by severity.
- **Inline Comments**: Optional `inline_comments` list, GitHub-review-style.
- **Natural Language Mode**: Set `natural_language: true` or `query: "explain issues in plain English"`.
- **Simple Frontend**: `/` serves `frontend/index.html` to try the API quickly.


## 🧱 Project Structure

pr-review-agent/ ├─ main.py ├─ services/ │ ├─ github_client.py │ └─ review_agent.py ├─ frontend/ │ └─ index.html ├─ requirements.txt ├─ Dockerfile ├─ .env.example ├─ README.md └─ .github/workflows/ci.yml

## 🔧 Local Setup
1. **Clone & enter**
```bash
git clone https://github.com/<you>/pr-review-agent.git
cd pr-review-agent

2. Python 3.10+ venv

python -m venv .venv
source .venv/bin/activate # Windows: .venv\Scripts\activate

3. Install deps

pip install -r requirements.txt

4. Configure env

cp .env.example .env
# Edit .env to set GITHUB_TOKEN (fine-grained, Pull Requests: Read)
export $(grep -v '^#' .env | xargs) # Windows: set manually

5. RUN

uvicorn main:app --reload --port 8000

6. Open UI: http://localhost:8000