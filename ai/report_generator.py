"""
AI Report Generator
====================
Uses Gemma 4 31B (via Gemini API) to generate a professional,
human-readable security audit report from raw scan results.

Input:  Combined scan results from all scanners
Output: Structured report with executive summary, findings,
        risk score, and prioritized recommendations
"""

import os
import json
import logging
from typing import Dict, Any, List

logger = logging.getLogger(__name__)


def generate_report(
    url: str,
    scan_results: List[Dict[str, Any]],
    user_uid: str = ""
) -> Dict[str, Any]:
    """
    Send scan results to Gemma 4 and get a structured security report.

    Args:
        url:          The scanned URL
        scan_results: List of results from each scanner module
        user_uid:     User identifier (for logging)

    Returns:
        Dictionary with full report, score, and recommendations
    """
    api_key = os.environ.get("GEMINI_API_KEY", "")
    model   = os.environ.get("GEMMA_MODEL", "gemma-4-31b-it")

    if not api_key:
        logger.error("GEMINI_API_KEY not set")
        return _error_report("Gemini API key not configured on server.")

    # ── Build the prompt ──────────────────────────────────────────────
    prompt = _build_prompt(url, scan_results)

    try:
        import google.generativeai as genai

        genai.configure(api_key=api_key)
        gemma = genai.GenerativeModel(
            model_name=model,
            system_instruction=_get_system_prompt()
        )

        logger.info(f"Generating report for {url} using {model}")
        response = gemma.generate_content(
            prompt,
            generation_config=genai.types.GenerationConfig(
                temperature=0.2,        # Low temp for consistent, factual reports
                max_output_tokens=4096,
                response_mime_type="application/json"
            )
        )

        raw_text = response.text.strip()

        # Clean JSON fences if present
        if raw_text.startswith("```"):
            raw_text = raw_text.split("```")[1]
            if raw_text.startswith("json"):
                raw_text = raw_text[4:]
        raw_text = raw_text.strip()

        report_data = json.loads(raw_text)
        logger.info(f"Report generated successfully for {url}")
        return report_data

    except json.JSONDecodeError as e:
        logger.error(f"Failed to parse Gemma JSON response: {e}")
        return _error_report(f"AI returned invalid JSON: {str(e)}")

    except Exception as e:
        logger.error(f"Gemma API error: {e}")
        return _error_report(str(e))


def _get_system_prompt() -> str:
    return """
You are a professional cybersecurity analyst generating security audit reports.
Your job is to analyze scan results and produce a clear, actionable security report.

RULES:
- Always respond with valid JSON only. No markdown. No explanations outside JSON.
- Be honest about severity. Don't downplay real risks.
- Use clear, non-technical language where possible so non-technical users understand.
- Prioritize recommendations by severity (critical first).
- Calculate a risk score from 0-100 where 100 = perfectly secure.
- The score should decrease based on the severity of issues found.
""".strip()


def _build_prompt(url: str, scan_results: List[Dict[str, Any]]) -> str:
    """Build the prompt sent to Gemma with all scan data."""

    # Calculate base score
    total_deduction = sum(r.get("score_deduction", 0) for r in scan_results)
    raw_score       = max(0, 100 - total_deduction)

    # Flatten all issues
    all_issues = []
    for result in scan_results:
        scanner = result.get("scanner", "unknown")
        for issue in result.get("issues", []):
            all_issues.append({
                "scanner":        scanner,
                "title":          issue.get("title", ""),
                "severity":       issue.get("severity", "info"),
                "description":    issue.get("description", ""),
                "recommendation": issue.get("recommendation", "")
            })

    scan_summary = json.dumps({
        "target_url":        url,
        "raw_score":         raw_score,
        "total_deduction":   total_deduction,
        "scanners_run":      [r.get("scanner") for r in scan_results],
        "all_issues":        all_issues,
        "issue_count":       len(all_issues),
        "critical_count":    sum(1 for i in all_issues if i["severity"] == "critical"),
        "high_count":        sum(1 for i in all_issues if i["severity"] == "high"),
        "medium_count":      sum(1 for i in all_issues if i["severity"] == "medium"),
        "low_count":         sum(1 for i in all_issues if i["severity"] == "low"),
    }, indent=2)

    return f"""
Analyze the following security scan results and generate a full security audit report.

SCAN DATA:
{scan_summary}

Generate a JSON report with EXACTLY this structure:
{{
  "target_url": "{url}",
  "security_score": <number 0-100>,
  "risk_level": "<one of: Critical / High / Medium / Low / Secure>",
  "executive_summary": "<2-3 sentence plain English summary of overall security posture>",
  "findings": [
    {{
      "title": "<issue title>",
      "severity": "<critical/high/medium/low/info>",
      "scanner": "<which scanner found this>",
      "description": "<clear explanation of the issue>",
      "impact": "<what could happen if this is exploited>",
      "recommendation": "<specific step to fix this>",
      "priority": <1 = fix immediately, 2 = fix soon, 3 = fix when possible>
    }}
  ],
  "top_priorities": [
    "<Priority 1 action>",
    "<Priority 2 action>",
    "<Priority 3 action>",
    "<Priority 4 action>",
    "<Priority 5 action>"
  ],
  "positive_findings": [
    "<things the site is doing well>"
  ],
  "scan_metadata": {{
    "scanners_run": <list of scanner names>,
    "total_issues_found": <number>,
    "critical_count": <number>,
    "high_count": <number>,
    "medium_count": <number>,
    "low_count": <number>
  }}
}}

Important: Sort findings by priority (critical first). Be specific and actionable.
""".strip()


def _error_report(reason: str) -> Dict[str, Any]:
    """Return a fallback report structure when AI fails."""
    return {
        "target_url":         "",
        "security_score":     0,
        "risk_level":         "Unknown",
        "executive_summary":  f"Report generation failed: {reason}",
        "findings":           [],
        "top_priorities":     ["Check server logs for details."],
        "positive_findings":  [],
        "scan_metadata":      {},
        "error":              reason
    }
