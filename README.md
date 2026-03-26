# IOC Checking and Risk Scoring

This tool performs checking of Indicators of Compromise (IOC) including IP addresses, domains, and file hashes using multiple threat intelligence sources. It also calculates a risk score and presents the results in a structured format.

---

## Features

* Supported IOC types:

  * IP Address
  * Domain
  * File Hash (MD5 / SHA256)

* Integrated data sources:

  * VirusTotal
  * AbuseIPDB
  * GreyNoise
  * OTX (AlienVault)
  * ThreatFox

* Risk scoring (0–100)

* Output:

  * Summary (High / Medium / Low)
  * Detailed checking per IOC

---

## Requirements

Python 3.8 or higher

Install dependencies:

```bash id="zj4m2x"
pip install -r requirements.txt
```

---

## API Keys Requirement

This tool requires API keys from external providers.

You must register and obtain API tokens from:

* VirusTotal
* AbuseIPDB
* GreyNoise
* OTX (AlienVault)
* ThreatFox

Without valid API keys, the tool will not function correctly.

---

## Environment Setup

Create a `.env` file in the project root:

```text id="x7n2pk"
VT_API_KEY=your_api_key
ABUSE_API_KEY=your_api_key
GREYNOISE_API_KEY=your_api_key
OTX_API_KEY=your_api_key
THREATFOX_API_KEY=your_api_key
```

---

## How to Run

```bash id="2d8y7c"
python IOC_Scoring.py
```

---

## Input

Provide up to 4 IOC values separated by commas without space:

Example:

```text id="h1r9qm"
185.220.101.1,example.com,44d88612fea8a8f36de82e1278abb02f
```

---

## Output

The program produces:

1. Summary:

   * Total IOC
   * High Risk
   * Medium Risk
   * Low Risk

2. Detailed Results:

   * Checking data from each source
   * Risk score

---

## Risk Scoring

The scoring model is based on multiple signals:

* VirusTotal
* ThreatFox
* AbuseIPDB
* OTX
* GreyNoise
* Network context (ISP, usage type)

Different IOC types use different weighting strategies.

---

## Disclaimer

This tool uses heuristic-based scoring.
A high score does not always guarantee malicious activity.
Use the results as decision support, not as a single source of truth.

