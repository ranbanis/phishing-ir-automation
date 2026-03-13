# Phishing IR Automation Script

A modular Python automation tool designed to accelerate the incident response process for user-reported phishing emails. The script parses raw `.eml` files, extracts observables, detonates URLs, and checks attachments against threat intelligence sources, outputting a structured JSON report for ticketing systems.

## Features
* **Header Analysis:** Extracts sender, recipient, subject, Reply-To, and Originating-IP.
* **URL Detonation:** Submits extracted URLs to URLScan.io for safe, out-of-band analysis.
* **Attachment Scanning:** Hashes attachments (SHA-256) and queries VirusTotal for malicious verdicts.
* **ServiceNow Ready:** Outputs a standardized JSON incident report mapping directly to standard IR ticket fields.

## Setup and Usage
1. Clone the repository: `git clone https://github.com/yourusername/phishing-ir-automation.git`
2. Install dependencies: `pip install -r requirements.txt`
3. Rename `.env.example` to `.env` and add your API keys.
4. Run the script against an `.eml` file: `python phishing_triage.py --file sample_phish.eml`
