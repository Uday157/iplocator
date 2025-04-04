import json
import csv

# Path to your downloaded NVD JSON file
json_file = "E:\\project\\nvdcve-1.1-modified.json"

# Output CSV file
csv_file = "E:\\project\\database.csv"

# Open JSON with utf-8 encoding
with open(json_file, "r", encoding="utf-8") as infile:
    data = json.load(infile)

cve_items = data.get("CVE_Items", [])

with open(csv_file, "w", newline='', encoding='utf-8') as outfile:
    writer = csv.writer(outfile)
    # CSV Header
    writer.writerow(["Product", "CWE", "CVE-ID", "Severity", "Base Score", "Description"])
    
    for item in cve_items:
        cve_id = item["cve"]["CVE_data_meta"]["ID"]
        description = item["cve"]["description"]["description_data"][0]["value"]
        
        # CWE might not always be present
        try:
            cwe = item["cve"]["problemtype"]["problemtype_data"][0]["description"][0]["value"]
        except:
            cwe = "N/A"

        # Get references and try to infer product from there or fallback to description
        try:
            product = item["cve"]["references"]["reference_data"][0]["name"]
        except:
            product = description.split(" ")[0]  # Fallback
        
        try:
            cvss = item["impact"]["baseMetricV3"]["cvssV3"]
            severity = cvss["baseSeverity"]
            score = cvss["baseScore"]
        except:
            severity = "UNKNOWN"
            score = "N/A"
        
        writer.writerow([product, cwe, cve_id, severity, score, description])

print(f"[+] Done! Saved data to {csv_file}")
