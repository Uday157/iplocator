import csv
import os

csv_file = os.path.join(os.path.dirname(__file__), "database.csv")

def load_vuln_db():
    vuln_db = []
    with open(csv_file, 'r', encoding='utf-8') as csvfile:
        reader = csv.reader(csvfile)
        next(reader)  # Skip header
        for row in reader:
            vuln_db.append(row)
    return vuln_db

def check_vulnerabilities(scan_result, vuln_db):
    findings = []

    for svc in scan_result['services']:
        parts = svc.split(',')
        if len(parts) < 3:
            continue  # Skip bad formats
        port = parts[0].strip()
        service_name = parts[1].strip().lower()
        version = parts[2].strip().lower()

        for row in vuln_db:
            try:
                db_product, db_cwe, db_cve, db_severity, db_score, db_description = row
                if service_name in db_product.lower():
                    findings.append({
                        "product": db_product.strip(),
                        "cwe": db_cwe.strip(),
                        "cve": db_cve.strip(),
                        "severity": db_severity.strip(),
                        "cvss_score": db_score.strip(),
                        "description": db_description.strip()
                    })
            except Exception as e:
                continue

    return findings
