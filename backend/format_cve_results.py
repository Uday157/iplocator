from bs4 import BeautifulSoup

# Path to the scan results file
scan_results_file = "E:/project/webapp/templates/scan_results.html"

def format_cve_results():
    with open(scan_results_file, "r", encoding="utf-8") as f:
        soup = BeautifulSoup(f, "html.parser")

    risk_section = soup.find("h2", string="⚠️ AI Predicted Risk Level:")
    if not risk_section:
        print("⚠️ AI Predicted Risk Level section not found.")
        return

    result = []
    current = risk_section.find_next_sibling()
    while current and current.name != "h2":  # Stop at next section
        if current.name == "p":
            text = current.get_text(strip=True)
            if "PORT:" in text and "SERVICE:" in text:
                result.append(f"\n{text}")
            elif "FOUND CVEs:" in text:
                cves = [li.get_text(strip=True) for li in current.find_all("li")]
                if cves:
                    result.extend([f"- {cve}" for cve in cves])
                else:
                    result.append("FOUND CVEs: OK")
        current = current.find_next_sibling()

    # Print formatted CVEs
    print("\n".join(result))

if __name__ == "__main__":
    format_cve_results()
