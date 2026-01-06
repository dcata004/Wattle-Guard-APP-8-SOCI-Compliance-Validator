import requests
import socket
import ssl
import datetime
import json
from urllib.parse import urlparse

# --- CONFIGURATION ---
# "Red Flag" jurisdictions for Australian Banks (Cloud Act risk)
HIGH_RISK_JURISDICTIONS = ["United States", "China", "Russia", "India"]

# "Green List" (GDPR Adequate or similar protections to Privacy Act 1988)
SAFE_JURISDICTIONS = ["Australia", "Switzerland", "United Kingdom", "Germany", "New Zealand"]

def get_server_location(domain):
    """
    Resolves IP and checks physical jurisdiction.
    Crucial for APP 8 (Cross-border disclosure).
    """
    try:
        ip_address = socket.gethostbyname(domain)
        # Using a public free API for demo (replace with paid DB in production)
        response = requests.get(f"http://ip-api.com/json/{ip_address}").json()
        return {
            "ip": ip_address,
            "country": response.get("country", "Unknown"),
            "region": response.get("regionName", "Unknown"),
            "isp": response.get("isp", "Unknown")
        }
    except Exception as e:
        return {"error": str(e)}

def check_ssl_security(domain):
    """
    Checks for APP 11 (Security of Personal Information) compliance.
    Verifies if data is encrypted in transit.
    """
    try:
        context = ssl.create_default_context()
        with socket.create_connection((domain, 443)) as sock:
            with context.wrap_socket(sock, server_hostname=domain) as ssock:
                cert = ssock.getpeercert()
                return {
                    "ssl_valid": True,
                    "cipher": ssock.cipher(),
                    "issuer": dict(x[0] for x in cert['issuer'])
                }
    except Exception:
        return {"ssl_valid": False, "note": "Connection Not Secure (Breach of APP 11)"}

def generate_risk_score(geo_data):
    """
    Calculates Risk based on SOCI Act & Privacy Act 1988 logic.
    """
    country = geo_data.get("country")
    
    if country == "Australia":
        return "LOW (Sovereign)", "Data resides within Australian jurisdiction."
    
    if country in HIGH_RISK_JURISDICTIONS:
        return "HIGH (Cloud Act Risk)", f"Server in {country}. Requires detailed APP 8.1 assessment."
    
    if country in SAFE_JURISDICTIONS:
        return "MEDIUM (GDPR Aligned)", f"Server in {country}. Likely compatible with APPs."
    
    return "UNKNOWN", "Manual review required."

def run_audit(target_url):
    print(f"🇦🇺 WATTLE-GUARD: Initiating APP 8 Sovereignty Audit for {target_url}...\n")
    
    # Clean URL
    domain = urlparse(target_url).netloc
    if not domain: domain = target_url # Handle raw domain input

    # 1. Sovereignty Check
    geo = get_server_location(domain)
    
    # 2. Security Check
    security = check_ssl_security(domain)
    
    # 3. Risk Calculation
    risk_level, risk_reason = generate_risk_score(geo)

    # 4. Generate Compliance Artifact
    report = {
        "timestamp": str(datetime.datetime.now()),
        "target": domain,
        "compliance_frameworks": ["Privacy Act 1988 (Cth)", "APP 8", "SOCI Act 2018"],
        "data_sovereignty": {
            "physical_location": f"{geo.get('region')}, {geo.get('country')}",
            "jurisdiction_risk": risk_level,
            "auditor_note": risk_reason
        },
        "app_11_security": {
            "encrypted_transit": security.get("ssl_valid"),
            "cipher_strength": security.get("cipher")
        },
        "recommendation": "PROCEED" if risk_level == "LOW (Sovereign)" else "STOP & ASSESS"
    }
    
    return report

if __name__ == "__main__":
    # Example Usage
    target = input("Enter Vendor URL to Audit (e.g. https://openai.com): ")
    audit_result = run_audit(target)
    
    print(json.dumps(audit_result, indent=4))
    
    # Penalty Warning Logic
    if audit_result['data_sovereignty']['jurisdiction_risk'].startswith("HIGH"):
        print("\n⚠️  WARNING: POTENTIAL APP 8 BREACH DETECTED.")
        print("   Under the new Privacy Legislation Amendment, max penalties allow for:")
        print("   - $50,000,000 AUD")
        print("   - Or 30% of adjusted turnover.")
