import json
import re
import requests

def check_vulnerability(package, version):
    OSV_API = "https://api.osv.dev/v1/query"

    payload = {
        "version": version,
        "package": {
            "name": package,
            "ecosystem": "PyPI"
        }
    }

    try:
        response = requests.post(
            OSV_API,
            json=payload,
            timeout=30
        )
    except requests.RequestException as error:
        print(f"OSV API request failed: {error}")
        return []

    if response.status_code != 200:
        return []

    data = response.json()

    return data.get("vulns", [])

def parse_requirements(filename):
    dependencies = []

    with open(filename, "r", encoding="utf-8") as file:
        for line in file:
            line = line.strip()

            if not line or line.startswith("#"):
                continue

            match = re.match(r"([A-Za-z0-9_.-]+)==(.+)", line)

            if match:
                package = match.group(1)
                version = match.group(2)

                dependencies.append({
                    "package": package,
                    "version": version
                })

    return dependencies

def generate_json_report(dependencies):
    count = 0
    report = []
    vulnerabilities_found = False

    for dependency in dependencies:
        package = dependency["package"]
        version = dependency["version"]

        vulnerabilities = check_vulnerability(package, version)

        if vulnerabilities:
            vulnerabilities_found = True
            count += 1

        report.append({
            "package": package,
            "version": version,
            "vulnerabilities": vulnerabilities
        })

    result = {
        "scan_type": "SCA",
        "packages_found": len(report),
        "vulnerabilities_found": vulnerabilities_found,
        "findings": report
    }

    with open("sca_report.json", "w", encoding="utf-8") as file:
        json.dump(result, file, indent=4, ensure_ascii=False)

    return vulnerabilities_found, count

if __name__ == "__main__":
    requirements_file = "requirements.txt"

    dependencies = parse_requirements(requirements_file)

    vulnerabilities_found, count = generate_json_report(dependencies)

    print(
        f"SCA analysis completed.\n"
        f"Packages: {len(dependencies)}\n"
        f"Findings: {count}"
    )
    # if count > 0:
    #     raise SystemExit(1)