import os
import json
import email
import hashlib
import argparse
import requests
from email import policy
from dotenv import load_dotenv

# Load environment variables
load_dotenv()
VT_API_KEY = os.getenv("VT_API_KEY")
URLSCAN_API_KEY = os.getenv("URLSCAN_API_KEY")

class EmailParser:
    """Handles the extraction of headers, body, and attachments from .eml files."""
    def __init__(self, file_path):
        self.file_path = file_path
        self.msg = self._load_email()

    def _load_email(self):
        with open(self.file_path, 'rb') as f:
            return email.message_from_binary_file(f, policy=policy.default)

    def get_headers(self):
        return {
            "Subject": self.msg.get("Subject", "No Subject"),
            "From": self.msg.get("From", "Unknown Sender"),
            "To": self.msg.get("To", "Unknown Recipient"),
            "Date": self.msg.get("Date", "Unknown Date"),
            "Reply-To": self.msg.get("Reply-To", "None"),
            "Message-ID": self.msg.get("Message-ID", "None")
        }

    def get_attachments(self):
        attachments = []
        for part in self.msg.walk():
            if part.get_content_maintype() == 'multipart' or part.get('Content-Disposition') is None:
                continue
            
            filename = part.get_filename()
            if filename:
                payload = part.get_payload(decode=True)
                sha256_hash = hashlib.sha256(payload).hexdigest()
                attachments.append({"filename": filename, "sha256": sha256_hash})
        return attachments

class ThreatIntelEnricher:
    """Interacts with external APIs for IOC analysis."""
    
    @staticmethod
    def check_virustotal(file_hash):
        if not VT_API_KEY:
            return {"error": "API Key missing", "mock_verdict": "clean"}
            
        url = f"https://www.virustotal.com/api/v3/files/{file_hash}"
        headers = {"x-apikey": VT_API_KEY}
        try:
            response = requests.get(url, headers=headers)
            if response.status_code == 200:
                stats = response.json().get('data', {}).get('attributes', {}).get('last_analysis_stats', {})
                return stats
            return {"error": f"HTTP {response.status_code}"}
        except Exception as e:
            return {"error": str(e)}

    @staticmethod
    def submit_urlscan(url_to_scan):
        if not URLSCAN_API_KEY:
            return {"error": "API Key missing", "mock_url": "https://urlscan.io/result/mock-uuid/"}
            
        url = "https://urlscan.io/api/v1/scan/"
        headers = {"API-Key": URLSCAN_API_KEY, "Content-Type": "application/json"}
        data = {"url": url_to_scan, "visibility": "private"}
        
        try:
            response = requests.post(url, headers=headers, json=data)
            if response.status_code == 200:
                return {"scan_url": response.json().get("result")}
            return {"error": f"HTTP {response.status_code}"}
        except Exception as e:
            return {"error": str(e)}

def main():
    parser = argparse.ArgumentParser(description="Automate Phishing Email Triage")
    parser.add_argument("-f", "--file", required=True, help="Path to the .eml file")
    args = parser.add_argument()
    args = parser.parse_args()

    print(f"[*] Parsing email: {args.file}...")
    email_data = EmailParser(args.file)
    headers = email_data.get_headers()
    attachments = email_data.get_attachments()

    enricher = ThreatIntelEnricher()
    
    # Process Attachments
    print("[*] Checking attachments against VirusTotal...")
    attachment_results = []
    for att in attachments:
        vt_stats = enricher.check_virustotal(att["sha256"])
        attachment_results.append({
            "filename": att["filename"],
            "sha256": att["sha256"],
            "vt_analysis": vt_stats
        })

    # Note: URL extraction logic from the email body would go here. 
    # For demonstration, we'll assume we extracted a suspicious URL.
    mock_extracted_url = "http://suspicious-login-update.com"
    print(f"[*] Detonating extracted URL: {mock_extracted_url} via URLScan...")
    urlscan_result = enricher.submit_urlscan(mock_extracted_url)

    # Construct the final JSON report
    incident_report = {
        "incident_type": "Phishing Attempt",
        "headers": headers,
        "indicators": {
            "attachments": attachment_results,
            "urls_scanned": [
                {
                    "url": mock_extracted_url,
                    "urlscan_report": urlscan_result
                }
            ]
        },
        "recommendation": "Review URLScan screenshot. If malicious, block domain at the proxy and purge email from inboxes."
    }

    print("\n=== FINAL INCIDENT REPORT (JSON) ===")
    print(json.dumps(incident_report, indent=4))
    
    # Optionally save to file
    with open('incident_report.json', 'w') as f:
        json.dump(incident_report, f, indent=4)
    print("[*] Report saved to incident_report.json")

if __name__ == "__main__":
    main()
