# cve_converter.py
import json
import csv

def convert_json_to_csv(json_file_path, csv_file_path):
    with open(json_file_path, "r", encoding='utf-8') as infile:
        data = json.load(infile)

    cve_items = data.get("CVE_Items", [])

    with open(csv_file_path, "w", newline='', encoding='utf-8') as outfile:
        writer = csv.writer(outfile)
        writer.writerow(["Product", "CWE", "CVE-ID", "Severity", "Base Score", "Description"])
        
        for item in cve_items:
            cve_id = item["cve"]["CVE_data_meta"]["ID"]
            description = item["cve"]["description"]["description_data"][0]["value"]
            
            try:
                cwe = item["cve"]["problemtype"]["problemtype_data"][0]["description"][0]["value"]
            except:
                cwe = "N/A"

            try:
                product = item["cve"]["references"]["reference_data"][0].get("name", "N/A")
            except:
                product = description.split(" ")[0]
            
            try:
                cvss = item["impact"]["baseMetricV3"]["cvssV3"]
                severity = cvss.get("baseSeverity", "UNKNOWN")
                score = cvss.get("baseScore", "N/A")
            except:
                severity = "UNKNOWN"
                score = "N/A"
            
            writer.writerow([product, cwe, cve_id, severity, score, description])

    print(f"[+] Conversion done! CSV saved to {csv_file_path}")
