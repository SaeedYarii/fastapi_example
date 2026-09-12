import os
import re
import json

def checking_files_locally(path):
    allfiles = []

    for root, dirs, files in os.walk(path):
        dirs[:] = [d for d in dirs if d not in {".git", ".github"}]

        for file in files:
            full_path = os.path.join(root, file)
            allfiles.append(full_path)

    return allfiles

def get_repo_content(local_dir=".."):
    file_paths = checking_files_locally(local_dir)
    results = {}

    for file_full_path in file_paths:
        try:
            with open(file_full_path, "r", encoding="utf-8", errors="ignore") as f:
                results[file_full_path] = f.read()
        except Exception:
            continue

    return results

def secret_scanning(content_dict):
    SECRET_PATTERNS = {
        "GitHub Token": r"\bgh[pousr]_[A-Za-z0-9_]{20,255}\b",
        "AWS Access Key": r"\bAKIA[0-9A-Z]{16}\b",
        "AWS Secret Access Key": r"(?i)\bAWS_SECRET_ACCESS_KEY\s*=\s*[\"']?[A-Za-z0-9/+=]{40}[\"']?",
        "Google API Key": r"\bAIza[0-9A-Za-z_-]{35}\b",
        "Stripe Secret Key": r"\bsk_(?:live|test)_[0-9A-Za-z]{20,}\b",
        "JWT": r"\beyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\b",
        "Password Assignment": r"""(?i)\b(?:password|passwd|pwd)\s*[:=]\s*["']?[^"'\s]+["']?""",
        "API Key Assignment": r"""(?i)\b(?:api[_-]?key|api[_-]?token)\s*[:=]\s*["']?[^"'\s]+["']?"""
    }

    findings = []

    for file_path, text in content_dict.items():
        lines = text.splitlines()

        for line_num, line in enumerate(lines, 1):
            for secret_type, pattern in SECRET_PATTERNS.items():
                match = re.search(pattern, line)

                if match:
                    findings.append({
                        "file": file_path,
                        "line": line_num,
                        "type": secret_type,
                        "evidence": match.group()
                    })

    return findings

def generate_json_report(findings):
    report = {
        "scan_type": "Secret Scanning",
        "total_findings": len(findings),
        "findings": findings
    }

    with open( "secret_scanning_report.json", "w", encoding="utf-8") as f:
        json.dump(report, f, indent=4, ensure_ascii=False)

if __name__ == "__main__":
    content = get_repo_content("..")

    secrets_found = secret_scanning(content)

    generate_json_report(secrets_found)

    print(
        f"Secret scanning completed.\n"
        f"Findings: {len(secrets_found)}"
    )

    # if secrets_found:
    #     raise SystemExit(1)