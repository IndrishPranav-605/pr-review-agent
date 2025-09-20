import re
from dataclasses import dataclass
from typing import List, Optional, Tuple


@dataclass
class ReviewFinding:
    file: str
    line: Optional[int]
    feedback: str
    severity: str  # "info", "warn", "error"
    rule: str      # short rule id (e.g., "complexity", "secrets")


@dataclass
class ReviewResult:
    score: int
    summary: str
    summary_natural: str


class ReviewEngine:
    """Heuristic review engine designed to be easily upgraded with AI.

    TODO (CodeMate AI Extension):
      - Replace/augment `generate_feedback` with AI-driven analysis.
    """

    SECRET_PATTERNS = [
        re.compile(r"AKIA[0-9A-Z]{16}"),  # AWS Access Key ID
        re.compile(r"(api_key|apikey|secret|password)\s*[:=]\s*['\"]?[A-Za-z0-9_\-]{12,}", re.I),
        re.compile(r"-----BEGIN (?:RSA|DSA|EC) PRIVATE KEY-----"),
    ]

    INSECURE_PATTERNS = [
        (re.compile(r"\beval\("), "Avoid eval(): code injection risk."),
        (re.compile(r"\bexec\("), "Avoid exec(): security & maintainability risk."),
        (re.compile(r"subprocess\.[A-Za-z_]+\(.*shell\s*=\s*True"), "subprocess with shell=True is dangerous; prefer list args."),
        (re.compile(r"pickle\.loads\("), "Untrusted pickle.loads can RCE; consider safer formats."),
        (re.compile(r"requests\.get\(.*verify\s*=\s*False"), "TLS verification disabled; restore verify=True."),
    ]

    def generate_feedback(self, diff_text: str, file: str) -> List[ReviewFinding]:
        """Parse a unified diff patch and run heuristics on added lines."""
        findings: List[ReviewFinding] = []
        for hunk, _ in self._iter_hunks(diff_text):
            added_lines: List[Tuple[int, str]] = [
                (ln, txt) for (op, txt, ln) in hunk if op == "+" and ln is not None
            ]

            findings.extend(self._check_missing_docstrings(file, hunk))
            findings.extend(self._check_todos(file, added_lines))
            findings.extend(self._check_insecure(file, added_lines))
            findings.extend(self._check_secrets(file, added_lines))
            findings.extend(self._check_style(file, added_lines))
            findings.extend(self._check_complexity(file, hunk))

        return findings

    # ------------------------ Scoring & Summary ------------------------

    def summarize_and_score(self, findings: List[ReviewFinding]) -> ReviewResult:
        score = 100
        penalties = {
            "secrets": 40, "insecure": 25, "complexity": 10, "style": 5,
            "missing-doc": 6, "todo": 2, "no-text-diff": 0
        }

        by_rule = {}
        for f in findings:
            by_rule.setdefault(f.rule, 0)
            by_rule[f.rule] += 1

        for rule, count in by_rule.items():
            p = penalties.get(rule, 3)
            score -= min(90, p * count)

        score = max(0, min(100, score))

        parts = [f"Total findings: {len(findings)}. Score: {score}/100."]
        for rule, count in sorted(by_rule.items(), key=lambda x: -x[1]):
            parts.append(f"{rule}: {count}")
        summary = " | ".join(parts)

        nl_bits = []
        if by_rule.get("secrets"):
            nl_bits.append("I spotted potential secrets—please remove them and use env vars or a vault.")
        if by_rule.get("insecure"):
            nl_bits.append("There are a few security risks (eval/exec, shell=True, etc.).")
        if by_rule.get("missing-doc"):
            nl_bits.append("Some new functions/classes lack docstrings; add short explanations.")
        if by_rule.get("complexity"):
            nl_bits.append("A few blocks look complex or deeply nested; refactor for clarity.")
        if by_rule.get("style"):
            nl_bits.append("Minor style issues (long lines, trailing spaces, magic numbers).")
        if not nl_bits:
            nl_bits.append("Looks clean overall. Nice job keeping changes readable and safe!")

        summary_natural = " ".join(nl_bits) + f" Overall code health score: {score}/100."

        return ReviewResult(score=score, summary=summary, summary_natural=summary_natural)

    # ------------------------ Diff Parsing ------------------------

    def _iter_hunks(self, patch: str):
        """Yield (hunk_lines, start_line_right) for each @@ block."""
        lines = patch.splitlines()
        i = 0
        while i < len(lines):
            line = lines[i]
            if line.startswith("@@ "):
                m = re.search(r"@@ -\d+(?:,\d+)? \+(\d+)(?:,(\d+))? @@", line)
                right_start = int(m.group(1)) if m else 1
                right_lineno = right_start
                i += 1
                hunk = [("@", line, None)]
                while i < len(lines) and not lines[i].startswith("@@ "):
                    l = lines[i]
                    if l.startswith("+"):
                        hunk.append(("+", l[1:], right_lineno))
                        right_lineno += 1
                    elif l.startswith("-"):
                        hunk.append(("-", l[1:], None))
                    else:
                        hunk.append((" ", l[1:] if l.startswith(" ") else l, right_lineno))
                        right_lineno += 1
                    i += 1
                yield hunk, right_start
            else:
                i += 1

    # ------------------------ Heuristics ------------------------

    def _check_missing_docstrings(self, file: str, hunk) -> List[ReviewFinding]:
        findings: List[ReviewFinding] = []
        for op, txt, ln in hunk:
            if op == "+":
                if re.match(r"\s*def\s+\w+\(.*\):\s*$", txt) or re.match(r"\s*class\s+\w+\s*\(?\w*\)?:\s*$", txt):
                    findings.append(
                        ReviewFinding(
                            file=file,
                            line=ln,
                            feedback="Public defs/classes should start with a docstring.",
                            severity="info",
                            rule="missing-doc",
                        )
                    )
        return findings

    def _check_todos(self, file: str, added: List[Tuple[int, str]]) -> List[ReviewFinding]:
        out: List[ReviewFinding] = []
        for ln, txt in added:
            if re.search(r"\b(TODO|FIXME|XXX)\b", txt):
                out.append(
                    ReviewFinding(
                        file=file,
                        line=ln,
                        feedback="Leftover TODO/FIXME found—consider resolving before merge.",
                        severity="info",
                        rule="todo",
                    )
                )
        return out

    def _check_insecure(self, file: str, added: List[Tuple[int, str]]) -> List[ReviewFinding]:
        out: List[ReviewFinding] = []
        for ln, txt in added:
            for pat, msg in self.INSECURE_PATTERNS:
                if pat.search(txt):
                    out.append(
                        ReviewFinding(file=file, line=ln, feedback=msg, severity="error", rule="insecure")
                    )
        return out

    def _check_secrets(self, file: str, added: List[Tuple[int, str]]) -> List[ReviewFinding]:
        out: List[ReviewFinding] = []
        for ln, txt in added:
            for pat in self.SECRET_PATTERNS:
                if pat.search(txt):
                    out.append(
                        ReviewFinding(
                            file=file,
                            line=ln,
                            feedback="Potential secret detected; remove from code and rotate credentials.",
                            severity="error",
                            rule="secrets",
                        )
                    )
        return out

    def _check_style(self, file: str, added: List[Tuple[int, str]]) -> List[ReviewFinding]:
        out: List[ReviewFinding] = []
        for ln, txt in added:
            if len(txt) > 120:
                out.append(ReviewFinding(file=file, line=ln, feedback="Line exceeds 120 chars.", severity="warn", rule="style"))
            if txt.rstrip() != txt:
                out.append(ReviewFinding(file=file, line=ln, feedback="Trailing whitespace.", severity="info", rule="style"))
            if "\t" in txt:
                out.append(ReviewFinding(file=file, line=ln, feedback="Tab character found; prefer spaces.", severity="info", rule="style"))
            if re.search(r"\bprint\(", txt):
                out.append(ReviewFinding(file=file, line=ln, feedback="Avoid print() in production; use logging.", severity="info", rule="style"))
            if re.search(r"\b\d{3,}\b", txt) and not re.search(r"(0x[0-9a-fA-F]+|[A-Z_]{3,})", txt):
                out.append(ReviewFinding(file=file, line=ln, feedback="Magic number—consider named constant.", severity="info", rule="style"))
        return out

    def _check_complexity(self, file: str, hunk) -> List[ReviewFinding]:
        out: List[ReviewFinding] = []
        added_ops = 0
        max_nesting = 0
        for op, txt, ln in hunk:
            if op == "+":
                added_ops += len(re.findall(r"\b(if|for|while|try|with|except|match|case)\b", txt))
                indent = len(txt) - len(txt.lstrip(" "))
                level = indent // 4
                max_nesting = max(max_nesting, level)
        if added_ops >= 6 or max_nesting >= 3:
            first_added_line = next((ln for (op, _t, ln) in hunk if op == "+" and ln is not None), None)
            out.append(
                ReviewFinding(
                    file=file,
                    line=first_added_line,
                    feedback="High logical complexity detected—consider refactoring.",
                    severity="warn",
                    rule="complexity",
                )
            )
        return out
