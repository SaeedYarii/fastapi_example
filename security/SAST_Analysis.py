import os
import json
import ast
import re

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

def create_finding(
    rule_id,
    vulnerability,
    severity,
    file_path,
    line,
    message
):
    return {
        "rule_id": rule_id,
        "vulnerability": vulnerability,
        "severity": severity,
        "file": file_path,
        "line": line,
        "message": message
    }

class SecurityAnalyzer(ast.NodeVisitor):
    def __init__(self, file_path):
        self.file_path = file_path
        self.findings = []

    def visit_Call(self, node):
        if isinstance(node.func, ast.Name):
            if node.func.id == "eval":
                self.findings.append(
                    create_finding(
                        "SAST-001",
                        "Dangerous eval()",
                        "CRITICAL",
                        self.file_path,
                        node.lineno,
                        "eval() can execute arbitrary Python code."
                    )
                )

        if isinstance(node.func, ast.Attribute):
            if (
                isinstance(node.func.value, ast.Name)
                and node.func.value.id == "os"
                and node.func.attr == "system"
            ):
                self.findings.append(
                    create_finding(
                        "SAST-002",
                        "Command Injection",
                        "CRITICAL",
                        self.file_path,
                        node.lineno,
                        "os.system() may execute attacker-controlled commands."
                    )
                )

        if isinstance(node.func, ast.Attribute):
            if node.func.attr in {
                "run",
                "call",
                "Popen",
                "check_output"
            }:

                for keyword in node.keywords:

                    if keyword.arg == "shell":

                        if (isinstance(keyword.value, ast.Constant) and keyword.value.value is True):
                            self.findings.append(
                                create_finding(
                                    "SAST-003",
                                    "Command Injection",
                                    "CRITICAL",
                                    self.file_path,
                                    node.lineno,
                                    "subprocess is executed with shell=True."
                                )
                            )

        if isinstance(node.func, ast.Attribute):
            if node.func.attr in {"execute", "executemany"}:
                for argument in node.args:
                    if self.is_dynamic_string(argument):
                        self.findings.append(
                            create_finding(
                                "SAST-004",
                                "SQL Injection",
                                "HIGH",
                                self.file_path,
                                node.lineno,
                                "SQL query is constructed using dynamic input."
                            )
                        )

        if isinstance(node.func, ast.Attribute):
            if node.func.attr.lower() in {"md5", "sha1"}:
                self.findings.append(
                    create_finding(
                        "SAST-005",
                        "Weak Cryptography",
                        "MEDIUM",
                        self.file_path,
                        node.lineno,
                        f"Weak cryptographic algorithm {node.func.attr}"
                    )
                )

        if (
            isinstance(node.func, ast.Name)
            and node.func.id == "open"
        ):
            if node.args:
                argument = node.args[0]

                if self.is_dynamic_string(argument):
                    self.findings.append(
                        create_finding(
                            "SAST-006",
                            "Path Traversal",
                            "HIGH",
                            self.file_path,
                            node.lineno,
                            "File path is dynamically constructed."
                        )
                    )

        if isinstance(node.func, ast.Attribute):
            if node.func.attr in {
                "get",
                "post",
                "put",
                "delete",
                "request"
            }:

                for keyword in node.keywords:
                    if keyword.arg == "verify":
                        if (
                            isinstance(keyword.value, ast.Constant)
                            and keyword.value.value is False
                        ):
                            self.findings.append(
                                create_finding(
                                    "SAST-007",
                                    "Disabled TLS Verification",
                                    "HIGH",
                                    self.file_path,
                                    node.lineno,
                                    "TLS certificate verification is disabled."
                                )
                            )

        self.generic_visit(node)

    def is_dynamic_string(self, node):
        if isinstance(node, ast.BinOp):

            if isinstance(node.op, ast.Add):
                return True

            if isinstance(node.op, ast.Mod):
                return True

        if isinstance(node, ast.JoinedStr):
            return True

        return False

def analyze_hardcoded_secrets(file_path, content):
    findings = []
    patterns = [
        (
            "SAST-008",
            r'(?i)(password|passwd|pwd)\s*=\s*["\'][^"\']+["\']',
            "Hardcoded Password",
            "Possible hardcoded password."
        ),
        (
            "SAST-009",
            r'(?i)(api_key|apikey)\s*=\s*["\'][^"\']+["\']',
            "Hardcoded API Key",
            "Possible hardcoded API key."
        ),
        (
            "SAST-010",
            r'(?i)(secret_key|secretkey)\s*=\s*["\'][^"\']+["\']',
            "Hardcoded Secret",
            "Possible hardcoded secret."
        ),
        (
            "SAST-011",
            r'AKIA[0-9A-Z]{16}',
            "Hardcoded AWS Credential",
            "Possible AWS access key."
        )
    ]

    lines = content.splitlines()

    for line_number, line in enumerate(lines, start=1):
        for (rule_id, pattern, vulnerability, message) in patterns:

            if re.search(pattern, line):
                severity = "CRITICAL"

                if rule_id in {"SAST-008", "SAST-009", "SAST-010"}:
                    severity = "HIGH"

                findings.append(
                    create_finding(
                        rule_id,
                        vulnerability,
                        severity,
                        file_path,
                        line_number,
                        message
                    )
                )

    return findings

def analyze_code(file_path, content):
    findings = []

    if not file_path.endswith(".py"):
        return findings

    try:
        tree = ast.parse(content)
        analyzer = SecurityAnalyzer(file_path)
        analyzer.visit(tree)
        findings.extend(analyzer.findings)

    except SyntaxError as error:

        findings.append(
            create_finding(
                "SAST-000",
                "Syntax Error",
                "INFO",
                file_path,
                error.lineno or 0,
                "Python file could not be parsed."
            )
        )

    findings.extend(
        analyze_hardcoded_secrets(file_path, content)
    )

    return findings

def generate_json_report(files):
    report = []

    for file_path, content in files.items():

        findings = analyze_code(file_path, content)

        if findings:
            report.extend(findings)

    result = {
        "scan_type": "SAST",
        "files_scanned": len(files),
        "vulnerabilities_found": len(report),
        "findings": report
    }

    with open("sast_report.json", "w", encoding="utf-8") as file:
        json.dump(result, file, indent=4, ensure_ascii=False)

    return len(report)

if __name__ == "__main__":

    content = get_repo_content("..")

    findings_count = generate_json_report(content)

    print(
        f"SAST analysis completed.\n"
        f"Files: {len(content)}\n"
        f"Findings: {findings_count}"
    )

    # if findings_count > 0:
    #     raise SystemExit(1)