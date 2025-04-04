import sys
import os
import requests
from flask import Flask, render_template, request, jsonify, send_file

# Add backend folder to Python's module search path
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "backend")))

from main import scan_target, fingerprint_device, load_vuln_db, check_vulnerabilities, predict_risk, generate_pdf_report

app = Flask(__name__)

# Function to get IP Geolocation
def get_ip_geolocation(ip):
    url = f"http://ip-api.com/json/{ip}"
    try:
        response = requests.get(url, timeout=5)
        response.raise_for_status()
        data = response.json()
        
        if data.get("status") == "fail":
            return None

        return {
            "city": data.get("city", "Unknown"),
            "country": data.get("country", "Unknown"),
            "latitude": data.get("lat"),
            "longitude": data.get("lon"),
            "isp": data.get("isp", "Unknown"),
        }
    except requests.exceptions.RequestException as e:
        print(f"Error fetching geolocation: {e}")
        return None

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/scan', methods=['POST'])
def scan():
    ip = request.form.get('target')

    if not ip:
        return jsonify({"error": "No IP or domain provided!"}), 400

    scan_result = scan_target(ip)
    if not scan_result:
        return jsonify({"error": "Scan failed or invalid target!"}), 400

    open_ports = scan_result.get('open_ports', [])
    services = scan_result.get('services', [])
    
    device_type = fingerprint_device(scan_result)
    mac_address = scan_result.get('mac_address', 'N/A')
    os_info = scan_result.get('os', 'N/A')

    device_map = {
        "Unknown Device": 0, "Camera": 1, "Router": 2, "NAS": 3, "PC": 4, 
        "Mobile": 5, "Windows PC / Laptop": 6, "Linux PC / Laptop": 7, 
        "Apple Device": 8, "Network Printer": 9, "VoIP Device (SIP Server)": 10
    }
    device_numeric = device_map.get(device_type, 0)

    vuln_db = load_vuln_db()
    vulnerabilities = check_vulnerabilities(scan_result, vuln_db)

    avg_cvss = sum(float(v["cvss_score"]) for v in vulnerabilities if v["cvss_score"] != "N/A") / len(vulnerabilities) if vulnerabilities else 0.0
    risk_level = predict_risk(len(open_ports), len(services), avg_cvss, device_numeric)

    geo_info = get_ip_geolocation(ip)

    scan_data = {
        "ip": ip,
        "open_ports": open_ports,
        "services": services,
        "risk_level": risk_level,
        "device_type": device_type,
        "mac_address": mac_address,
        "os_info": os_info,
        "vulnerabilities": vulnerabilities,
        "city": geo_info["city"] if geo_info else "Unknown",
        "country": geo_info["country"] if geo_info else "Unknown",
        "latitude": geo_info["latitude"] if geo_info else None,
        "longitude": geo_info["longitude"] if geo_info else None,
        "isp": geo_info["isp"] if geo_info else "Unknown"
    }

    # Save the scan results in session (for PDF download)
    app.config["LAST_SCAN"] = scan_data

    return render_template('scan_results.html', **scan_data)

@app.route("/download_report", methods=["GET"])
def download_report():
    """ Generate and download a PDF scan report """
    scan_data = app.config.get("LAST_SCAN")
    
    if not scan_data:
        return jsonify({"error": "No scan data available. Please run a scan first!"}), 400

    pdf_path = generate_pdf_report(scan_data)
    return send_file(pdf_path, as_attachment=True)

if __name__ == '__main__':
    app.run(debug=True)
