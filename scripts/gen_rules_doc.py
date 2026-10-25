#!/usr/bin/env python3
"""
Generate rules/RULES.md documentation directly from rules/*.yaml rule definitions.
Rerunnable script to ensure documentation stays perfectly in sync with YAML rule catalogs.
"""

from pathlib import Path
import yaml

REPO_ROOT = Path(__file__).resolve().parent.parent
RULES_DIR = REPO_ROOT / "rules"
OUTPUT_MD = RULES_DIR / "RULES.md"


def load_yaml_rules(rules_dir: Path):
    rules = []
    # Only load top-level rule files, skipping exceptions.yaml
    for yf in sorted(rules_dir.glob("*.yaml")):
        if yf.name == "exceptions.yaml":
            continue
        with open(yf, "r", encoding="utf-8") as f:
            data = yaml.safe_load(f)
            if data and isinstance(data, dict) and "rules" in data:
                for r in data["rules"]:
                    r["_source_file"] = yf.name
                    rules.append(r)
    return rules


def generate_rules_markdown(rules):
    lines = [
        "# Security Scanner Rules Catalog",
        "",
        "This document is automatically generated from the rule definitions in `rules/*.yaml`.",
        "Run `python scripts/gen_rules_doc.py` to regenerate.",
        "",
        "## Summary of Rules",
        "",
        "| Rule ID | Title | Base Severity | Engine | Source Catalog |",
        "|---|---|---|---|---|",
    ]

    for r in rules:
        rule_id = r.get("id", "")
        title = r.get("title", "")
        severity = str(r.get("severity", "")).upper()
        engine = r.get("engine", "")
        src = r.get("_source_file", "")
        lines.append(f"| `{rule_id}` | {title} | `{severity}` | `{engine}` | `{src}` |")

    lines.extend([
        "",
        "---",
        "",
        "## Rule Details",
        "",
    ])

    for r in rules:
        rule_id = r.get("id", "")
        title = r.get("title", "")
        severity = str(r.get("severity", "")).upper()
        what_it_detects = r.get("what_it_detects") or r.get("message", "")
        why_risky = r.get("why_risky") or r.get("message", "")
        recommendation = r.get("recommendation", "")
        bad_example = (r.get("bad_example") or "").strip()
        fixed_example = (r.get("fixed_example") or "").strip()

        lines.extend([
            f"### `{rule_id}` - {title}",
            "",
            f"- **Base Severity:** `{severity}`",
            f"- **Engine:** `{r.get('engine', 'regex')}`",
            f"- **Target Globs:** `{', '.join(r.get('file_globs', []))}`",
            f"- **Raise in Production:** `{'true' if r.get('raise_in_production') else 'false'}`",
            f"- **What it detects:** {what_it_detects}",
            f"- **Why it's risky:** {why_risky}",
            f"- **Remediation:** {recommendation}",
            "",
            "#### Insecure Example",
            "```text",
            bad_example,
            "```",
            "",
            "#### Remediated Example",
            "```text",
            fixed_example,
            "```",
            "",
            "---",
            "",
        ])

    return "\n".join(lines).strip() + "\n"


def main():
    rules = load_yaml_rules(RULES_DIR)
    md_content = generate_rules_markdown(rules)
    OUTPUT_MD.write_text(md_content, encoding="utf-8")
    print(f"Successfully generated {OUTPUT_MD} with {len(rules)} rules.")


if __name__ == "__main__":
    main()
