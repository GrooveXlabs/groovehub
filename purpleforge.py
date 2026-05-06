"""PurpleForge integration — auto-generate MITRE maps, Sigma rules, atomic tests, and gap reports from scan findings."""

from __future__ import annotations

import json
import uuid
from datetime import datetime, timezone
from typing import Any

MITRE_MAP = {
    "hardcoded_secret": {
        "technique_id": "T1552.001",
        "technique_name": "Credentials In Files",
        "tactic": "Credential Access",
        "data_sources": ["File monitoring", "Code repository scans"],
    },
    "shell_execution": {
        "technique_id": "T1059.004",
        "technique_name": "Command Shell",
        "tactic": "Execution",
        "data_sources": ["Process monitoring (4688)", "Command-line logging"],
    },
    "ssrf": {
        "technique_id": "T1021.001",
        "technique_name": "Remote Desktop Protocol",
        "tactic": "Lateral Movement",
        "data_sources": ["Network connection logs", "Proxy logs"],
    },
    "eval_exec": {
        "technique_id": "T1059",
        "technique_name": "Command and Scripting Interpreter",
        "tactic": "Execution",
        "data_sources": ["Process monitoring", "Application logs"],
    },
    "weak_permissions": {
        "technique_id": "T1222",
        "technique_name": "File and Directory Permissions Modification",
        "tactic": "Defense Evasion",
        "data_sources": ["File integrity monitoring", "Audit logs"],
    },
    "no_input_validation": {
        "technique_id": "T1203",
        "technique_name": "Exploitation for Client Execution",
        "tactic": "Execution",
        "data_sources": ["Application logs", "WAF logs"],
    },
    "dependency_cve": {
        "technique_id": "T1190",
        "technique_name": "Exploit Public-Facing Application",
        "tactic": "Initial Access",
        "data_sources": ["WAF logs", "IDS/IPS logs", "Application logs"],
    },
    "missing_auth": {
        "technique_id": "T1078",
        "technique_name": "Valid Accounts",
        "tactic": "Initial Access",
        "data_sources": ["Authentication logs", "API gateway logs"],
    },
    "insecure_deserialization": {
        "technique_id": "T1059",
        "technique_name": "Command and Scripting Interpreter",
        "tactic": "Execution",
        "data_sources": ["Application logs", "Process monitoring"],
    },
    "path_traversal": {
        "technique_id": "T1083",
        "technique_name": "File and Directory Discovery",
        "tactic": "Discovery",
        "data_sources": ["File access logs", "Application logs"],
    },
}

SIGMA_TEMPLATES = {
    "shell_execution": {
        "title": "MCP Server Spawning Suspicious Child Process",
        "logsource": {"product": "windows", "service": "security"},
        "detection": {
            "selection_parent": {
                "EventID": 4688,
                "ParentProcessName|endswith": ["node.exe", "python.exe", "uv.exe", "npm.exe"],
            },
            "selection_child": {
                "NewProcessName|endswith": ["cmd.exe", "powershell.exe", "bash.exe", "sh.exe", "wscript.exe", "cscript.exe"],
            },
            "filter_legitimate": {
                "CommandLine|contains": ["npm run", "pytest", "black", "ruff", "pip install", "npm install"],
            },
            "condition": "selection_parent and selection_child and not filter_legitimate",
        },
        "level": "high",
        "tags": ["attack.execution", "attack.t1059.004", "attack.t1059.001"],
    },
    "ssrf": {
        "title": "MCP Server Making Internal Network Connection",
        "logsource": {"product": "windows"},
        "detection": {
            "selection": {
                "Initiated": "true",
                "DestinationIp|startswith": [
                    "10.", "172.16.", "172.17.", "172.18.", "172.19.", "172.20.",
                    "172.21.", "172.22.", "172.23.", "172.24.", "172.25.", "172.26.",
                    "172.27.", "172.28.", "172.29.", "172.30.", "172.31.", "192.168.",
                    "127.", "169.254.",
                ],
            },
            "filter": {
                "Image|endswith": ["svchost.exe", "lsass.exe", "services.exe"],
            },
            "condition": "selection and not filter",
        },
        "level": "medium",
        "tags": ["attack.lateral_movement", "attack.t1021.001"],
    },
    "hardcoded_secret": {
        "title": "Process Accessing Sensitive File Pattern",
        "logsource": {"product": "windows", "service": "security"},
        "detection": {
            "selection": {
                "EventID": 4663,
                "ObjectName|contains": [".env", "config.json", "secrets", "credentials", "api_keys", ".htpasswd"],
            },
            "filter_system": {
                "SubjectUserName|contains": ["SYSTEM", "NETWORK SERVICE", "LOCAL SERVICE"],
            },
            "condition": "selection and not filter_system",
        },
        "level": "medium",
        "tags": ["attack.credential_access", "attack.t1552.001"],
    },
    "eval_exec": {
        "title": "Suspicious Script Execution by MCP Runtime",
        "logsource": {"product": "windows", "service": "security"},
        "detection": {
            "selection": {
                "EventID": 4688,
                "ParentProcessName|endswith": ["node.exe", "python.exe"],
                "CommandLine|contains": ["eval(", "exec(", "Function(", "compile(", "__import__"],
            },
            "condition": "selection",
        },
        "level": "high",
        "tags": ["attack.execution", "attack.t1059"],
    },
    "no_input_validation": {
        "title": "Application Error Indicating Potential Injection",
        "logsource": {"product": "windows", "service": "application"},
        "detection": {
            "selection": {
                "EventID": [1000, 1001],
                "Message|contains": ["SyntaxError", "TypeError", "SQLSyntaxErrorException", "OSError", "FileNotFoundError"],
            },
            "condition": "selection",
        },
        "level": "low",
        "tags": ["attack.execution", "attack.t1203"],
    },
    "dependency_cve": {
        "title": "Suspicious Outbound Connection from Application Process",
        "logsource": {"product": "windows"},
        "detection": {
            "selection": {
                "Initiated": "true",
                "Image|endswith": ["node.exe", "python.exe", "java.exe"],
                "DestinationPort": [4444, 5555, 6666, 1337, 8080, 443],
            },
            "condition": "selection",
        },
        "level": "medium",
        "tags": ["attack.initial_access", "attack.t1190"],
    },
}

ATOMIC_TEMPLATES = {
    "shell_execution": '''# Atomic Test: T1059.004 — Command Shell via MCP Server
param([string]$TestGuid = "purpleforge-001")
Write-Host "[$TestGuid] Starting atomic test: Command Shell Execution" -ForegroundColor Cyan
$benignCommands = @("whoami", "hostname", "ipconfig /all 2>`$null")
foreach ($cmd in $benignCommands) {
    Write-Host "[$TestGuid] Executing: $cmd"
    try { $output = Invoke-Expression $cmd 2>`$null; Write-Host "[$TestGuid] Output: $output" -ForegroundColor Gray }
    catch { Write-Host "[$TestGuid] Error: $($_.Exception.Message)" -ForegroundColor Yellow }
}
Write-Host "[$TestGuid] Test complete. Check SIEM for Event ID 4688 with parent = node/python." -ForegroundColor Green
''',
    "ssrf": '''# Atomic Test: T1021.001 — SSRF via HTTP Request
param([string]$TestGuid = "purpleforge-002")
Write-Host "[$TestGuid] Starting atomic test: SSRF Simulation" -ForegroundColor Cyan
$internalEndpoints = @("http://localhost:8080/", "http://127.0.0.1:3000/", "http://[::1]:80/")
foreach ($url in $internalEndpoints) {
    try {
        $response = Invoke-WebRequest -Uri $url -TimeoutSec 2 -UseBasicParsing -ErrorAction Stop
        Write-Host "[$TestGuid] SSRF HIT: $url (Status: $($response.StatusCode))" -ForegroundColor Red
    } catch {
        Write-Host "[$TestGuid] SSRF MISS: $url" -ForegroundColor Gray
    }
}
Write-Host "[$TestGuid] Test complete. Check proxy/network logs for internal requests from app process." -ForegroundColor Green
''',
    "hardcoded_secret": '''# Atomic Test: T1552.001 — Credential Access via File Read
param([string]$TestGuid = "purpleforge-003")
Write-Host "[$TestGuid] Starting atomic test: Credential File Access" -ForegroundColor Cyan
$tempFile = "$env:TEMP\test_credentials_$(Get-Random).tmp"
@"
API_KEY=pk_test_dummy_key_$(Get-Random)
SECRET=sk_test_dummy_secret_$(Get-Random)
"@ | Out-File -FilePath $tempFile -Encoding utf8
Write-Host "[$TestGuid] Created dummy credential file: $tempFile"
$content = Get-Content $tempFile -Raw
Write-Host "[$TestGuid] Read content (first 50 chars): $($content.Substring(0,[Math]::Min(50,$content.Length)))"
Remove-Item $tempFile -ErrorAction SilentlyContinue
Write-Host "[$TestGuid] Test complete. Check for file access events on .env/config files." -ForegroundColor Green
''',
    "eval_exec": '''# Atomic Test: T1059 — Code Injection via Eval
param([string]$TestGuid = "purpleforge-004")
Write-Host "[$TestGuid] Starting atomic test: Eval/Exec Simulation" -ForegroundColor Cyan
$expressions = @("2+2", "[Math]::Sqrt(16)", "Get-Date")
foreach ($expr in $expressions) {
    Write-Host "[$TestGuid] Evaluating: $expr"
    $result = Invoke-Expression $expr
    Write-Host "[$TestGuid] Result: $result" -ForegroundColor Gray
}
Write-Host "[$TestGuid] Test complete. Check application logs for suspicious eval/exec calls." -ForegroundColor Green
''',
    "no_input_validation": '''# Atomic Test: T1203 — Exploitation for Client Execution
param([string]$TestGuid = "purpleforge-005")
Write-Host "[$TestGuid] Starting atomic test: Input Validation Bypass" -ForegroundColor Cyan
$testInputs = @("A" * 1000, "'; SELECT 1; --", "../../etc/passwd", "<script>alert(1)</script>")
foreach ($input in $testInputs) {
    Write-Host "[$TestGuid] Testing input length $($input.Length): $($input.Substring(0,[Math]::Min(50,$input.Length)))..."
}
Write-Host "[$TestGuid] Test complete. Check application error logs for unexpected exceptions." -ForegroundColor Green
''',
    "dependency_cve": '''# Atomic Test: T1190 — Exploit Public-Facing Application
param([string]$TestGuid = "purpleforge-006")
Write-Host "[$TestGuid] Starting atomic test: Vulnerable Dependency Check" -ForegroundColor Cyan
if (Get-Command pip -ErrorAction SilentlyContinue) {
    Write-Host "[$TestGuid] Checking pip packages..."
    pip list --format=json 2>$null | ConvertFrom-Json | Where-Object { $_.version -match "^0\\." -or $_.version -match "^1\\.0\\." } | Select-Object -First 5
}
if (Test-Path "package.json") {
    Write-Host "[$TestGuid] Checking Node packages..."
    Get-Content package.json -Raw | ConvertFrom-Json | Select-Object -ExpandProperty dependencies -ErrorAction SilentlyContinue
}
Write-Host "[$TestGuid] Test complete. Review package versions against CVE databases." -ForegroundColor Green
''',
}


def _classify(finding_type: str) -> str | None:
    """Normalize finding type to a classification key."""
    normalized = finding_type.lower().replace(" ", "_").replace("-", "_")
    for key in list(MITRE_MAP.keys()) + list(SIGMA_TEMPLATES.keys()) + list(ATOMIC_TEMPLATES.keys()):
        if key in normalized or normalized in key:
            return key
    return None


def _dict_to_yaml(d: dict, indent: int = 0) -> list[str]:
    prefix = "  " * indent
    lines = []
    for k, v in d.items():
        if isinstance(v, dict):
            lines.append(f"{prefix}{k}:")
            lines.extend(_dict_to_yaml(v, indent + 1))
        elif isinstance(v, list):
            lines.append(f"{prefix}{k}:")
            for item in v:
                lines.append(f"{prefix}  - {item}")
        else:
            lines.append(f"{prefix}{k}: {v}")
    return lines


def generate_mitre_map(findings: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Map findings to MITRE ATT&CK techniques."""
    mapped = []
    for finding in findings:
        ftype = finding.get("rule_id", finding.get("type", "unknown"))
        key = _classify(ftype)
        mapping = MITRE_MAP.get(key) if key else {
            "technique_id": "T1595",
            "technique_name": "Unknown / Manual Mapping Required",
            "tactic": "Unknown",
            "data_sources": ["Manual analysis required"],
        }
        mapped.append({
            "finding_type": ftype,
            "severity": finding.get("severity", "MEDIUM"),
            "mitre": mapping,
        })
    return mapped


def generate_sigma_rules(findings: list[dict[str, Any]]) -> list[dict[str, str]]:
    """Generate Sigma YAML rules from findings."""
    rules = []
    seen = set()
    for finding in findings:
        ftype = finding.get("rule_id", finding.get("type", "unknown"))
        key = _classify(ftype)
        if key in seen:
            continue
        seen.add(key)

        template = SIGMA_TEMPLATES.get(key)
        if not template:
            continue

        lines = [
            f"title: {template['title']}",
            f"id: {uuid.uuid4()}",
            f"status: experimental",
            f"description: Auto-generated from GrooveGuard finding: {ftype}",
            f"author: PurpleForge / GrooveHub",
            f"date: {datetime.now(timezone.utc).strftime('%Y/%m/%d')}",
            f"logsource:",
        ]
        for k, v in template["logsource"].items():
            lines.append(f"  {k}: {v}")
        lines.append("detection:")
        lines.extend(_dict_to_yaml(template["detection"], indent=2))
        lines.extend([
            "falsepositives:",
            "  - Legitimate application behavior",
            f"level: {template['level']}",
            "tags:",
        ])
        for tag in template.get("tags", []):
            lines.append(f"  - {tag}")

        rules.append({
            "filename": f"grooveguard_{key}.yml",
            "content": "\n".join(lines) + "\n",
        })
    return rules


def generate_atomic_tests(findings: list[dict[str, Any]]) -> list[dict[str, str]]:
    """Generate PowerShell atomic tests from findings."""
    tests = []
    seen = set()
    for finding in findings:
        ftype = finding.get("rule_id", finding.get("type", "unknown"))
        key = _classify(ftype)
        if not key or key in seen:
            continue
        seen.add(key)

        content = ATOMIC_TEMPLATES.get(key)
        if not content:
            continue

        tests.append({
            "filename": f"grooveguard_{key}.ps1",
            "content": content,
        })
    return tests


def generate_gap_report(findings: list[dict[str, Any]], sigma_rules: list, atomic_tests: list) -> str:
    """Generate a gap analysis markdown report."""
    sigma_types = set()
    for rule in sigma_rules:
        name = rule["filename"].replace("grooveguard_", "").replace(".yml", "")
        sigma_types.add(name)

    atomic_types = set()
    for test in atomic_tests:
        name = test["filename"].replace("grooveguard_", "").replace(".ps1", "")
        atomic_types.add(name)

    rows = []
    seen_types = set()
    for finding in findings:
        ftype = finding.get("rule_id", finding.get("type", "unknown"))
        key = _classify(ftype)
        if not key or key in seen_types:
            continue
        seen_types.add(key)

        has_sigma = key in sigma_types
        has_atomic = key in atomic_types
        if has_sigma and has_atomic:
            coverage = "High"
        elif has_sigma or has_atomic:
            coverage = "Medium"
        else:
            coverage = "None"

        rows.append({
            "finding": ftype,
            "severity": finding.get("severity", "MEDIUM"),
            "sigma": "✅" if has_sigma else "❌",
            "atomic": "✅" if has_atomic else "❌",
            "coverage": coverage,
        })

    md = "# Purple Team Gap Analysis Report\n\n"
    md += f"**Total Findings**: {len(rows)}\n\n"
    md += "| Finding | Severity | Sigma Rule | Atomic Test | Coverage |\n"
    md += "|---------|----------|------------|-------------|----------|\n"

    for row in rows:
        md += f"| {row['finding']} | {row['severity']} | {row['sigma']} | {row['atomic']} | {row['coverage']} |\n"

    recommendations = []
    for row in rows:
        if row["coverage"] == "None":
            recommendations.append(f"Build both Sigma rule and atomic test for **{row['finding']}**")
        elif row["sigma"] == "❌":
            recommendations.append(f"Build Sigma rule for **{row['finding']}**")
        elif row["atomic"] == "❌":
            recommendations.append(f"Build atomic test for **{row['finding']}**")

    if recommendations:
        md += "\n## Recommendations\n\n"
        for i, rec in enumerate(recommendations, 1):
            md += f"{i}. {rec}\n"

    high = sum(1 for r in rows if r["coverage"] == "High")
    medium = sum(1 for r in rows if r["coverage"] == "Medium")
    none = sum(1 for r in rows if r["coverage"] == "None")
    rate = ((high + medium * 0.5) / max(len(rows), 1) * 100)

    md += f"\n## Summary\n\n"
    md += f"- **High Coverage**: {high}/{len(rows)}\n"
    md += f"- **Medium Coverage**: {medium}/{len(rows)}\n"
    md += f"- **No Coverage**: {none}/{len(rows)}\n"
    md += f"- **Coverage Rate**: {rate:.0f}%\n"

    return md


def generate_all_artifacts(findings: list[dict[str, Any]]) -> dict[str, Any]:
    """Generate all PurpleForge artifacts from a list of findings."""
    mitre = generate_mitre_map(findings)
    sigma = generate_sigma_rules(findings)
    atomic = generate_atomic_tests(findings)
    gap = generate_gap_report(findings, sigma, atomic)

    return {
        "mitre": json.dumps(mitre, indent=2),
        "sigma_rules": sigma,
        "atomic_tests": atomic,
        "gap_report": gap,
    }
