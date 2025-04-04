import os
import sys

sys.path.append(os.path.dirname(__file__))

from scanner import scan_target
from fingerprint import fingerprint_device
from vuln_check import load_vuln_db, check_vulnerabilities
from cve_converter import convert_json_to_csv
from predict_risk import predict_risk

# Updated dynamic paths
base_dir = os.path.dirname(__file__)
json_file = os.path.join(base_dir, "nvdcve-1.1-modified.json")
csv_file = os.path.join(base_dir, "database.csv")

if not os.path.exists(csv_file) or os.path.getsize(csv_file) == 0:
    print("[INFO] No CSV file found. Converting JSON to CSV...")
    convert_json_to_csv(json_file, csv_file)


def main():
    ip = input("Enter target IP: ")

    # 🔹 Run the scan
    scan_result = scan_target(ip)
    if not scan_result:
        print("[!] Scan failed or no data returned.")
        return

    print("\n[+] Scan Completed:")
    print(f"IP = {scan_result['ip']}")
    print(f"Open Ports: {', '.join(map(str, scan_result['open_ports']))}")

    print("\nServices Detected:")
    for svc in scan_result['services']:
        print(f"    {svc}")

    # 🔹 Display MAC Address and OS if available
    mac_address = scan_result.get('mac_address', 'N/A')
    os_info = scan_result.get('os', 'N/A')

    print(f"\nMAC Address: {mac_address}")
    print(f"Operating System: {os_info}")

    # 🔹 Identify Device Type
    device_type = fingerprint_device(scan_result)
    print(f"\n[+] Detected Device Type: {device_type}")

    # 🔹 Load Vulnerability Database
    vuln_db = load_vuln_db()
    vulnerabilities = check_vulnerabilities(scan_result, vuln_db)

    structured_vulns = []
    avg_cvss = 0.0

    if vulnerabilities:
        print("\n[!] Vulnerabilities Found:")
        scores = []
        
        for vuln in vulnerabilities:
            try:
                score = float(vuln["cvss_score"]) if vuln["cvss_score"] != "N/A" else 0.0
                scores.append(score)
                structured_vulns.append(vuln)

                predicted_risk = predict_risk(len(scan_result['open_ports']), len(scan_result['services']), score, 0)
                print(f"    [!] {vuln['cve']} - {vuln['severity']} (CVSS: {score})")
                print(f"    [AI Prediction] Risk Level: {predicted_risk}\n")

            except Exception as e:
                print(f"[!] Error parsing vulnerability data: {e}")
                continue

        avg_cvss = sum(scores) / len(scores) if scores else 0.0
    else:
        print("\n[+] No known vulnerabilities found (based on database.csv)")
        avg_cvss = 0.0

    # 🔹 Convert Device Type to Numeric for AI Model
    open_ports = len(scan_result['open_ports'])
    services = len(scan_result['services'])
    device_map = {
        "Unknown Device": 0, "Camera": 1, "Router": 2, "NAS": 3, "PC": 4, 
        "Mobile": 5, "Windows PC / Laptop": 6, "Linux PC / Laptop": 7, 
        "Apple Device": 8, "Network Printer": 9, "VoIP Device (SIP Server)": 10
    }
    device_numeric = device_map.get(device_type, 0)

    overall_risk = predict_risk(open_ports, services, avg_cvss, device_numeric)
    print(f"\n[+] AI Predicted Overall Risk Level: {overall_risk}")

    # 🔹 Return Structured Data (for Web App)
    return {
        "ip": scan_result["ip"],
        "open_ports": scan_result["open_ports"],
        "services": scan_result["services"],
        "mac_address": mac_address,
        "os": os_info,
        "device_type": device_type,
        "risk_level": overall_risk,
        "vulnerabilities": structured_vulns,
    }

from reportlab.lib.pagesizes import letter
from reportlab.pdfgen import canvas

def generate_pdf_report(scan_data, output_path="scan_report.pdf"):
    """
    Generates a PDF report from the scan data.
    
    :param scan_data: Dictionary containing scan results.
    :param output_path: Path to save the PDF file.
    """
    c = canvas.Canvas(output_path, pagesize=letter)
    width, height = letter

    c.setFont("Helvetica-Bold", 16)
    c.drawString(50, height - 50, "Network Security Scan Report")

    c.setFont("Helvetica", 12)
    y_position = height - 100

    def draw_text(label, value):
        """Helper function to print text lines in PDF."""
        nonlocal y_position
        c.drawString(50, y_position, f"{label}: {value}")
        y_position -= 20

    draw_text("Target IP", scan_data.get("ip", "N/A"))
    draw_text("Device Type", scan_data.get("device_type", "N/A"))
    draw_text("Operating System", scan_data.get("os", "N/A"))
    draw_text("MAC Address", scan_data.get("mac_address", "N/A"))
    draw_text("Risk Level", scan_data.get("risk_level", "N/A"))

    c.setFont("Helvetica-Bold", 12)
    y_position -= 10
    c.drawString(50, y_position, "Open Ports and Services:")
    c.setFont("Helvetica", 12)
    y_position -= 20

    for service in scan_data.get("services", []):
        if y_position < 50:
            c.showPage()
            c.setFont("Helvetica", 12)
            y_position = height - 50

        c.drawString(60, y_position, service)
        y_position -= 15

    c.setFont("Helvetica-Bold", 12)
    y_position -= 10
    c.drawString(50, y_position, "Vulnerabilities:")
    c.setFont("Helvetica", 12)
    y_position -= 20

    for vuln in scan_data.get("vulnerabilities", []):
        if y_position < 50:
            c.showPage()
            c.setFont("Helvetica", 12)
            y_position = height - 50

        c.drawString(60, y_position, f"{vuln['cve']} - {vuln['severity']} (CVSS: {vuln['cvss_score']})")
        y_position -= 15

    c.save()
    return output_path


if __name__ == "__main__":
    main()
