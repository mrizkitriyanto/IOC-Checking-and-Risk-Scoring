# Author: mastoto
# Tool  : IOC Enrichment & Risk Scoring
# Version: 1.0
# Scoring is heuristic-based and should be used as decision support, not as a single source of truth.

import requests
import ipaddress
import re
from concurrent.futures import ThreadPoolExecutor, as_completed
from dotenv import load_dotenv
import os
import json
from datetime import datetime

load_dotenv()

VT_API_KEY = os.getenv("VT_API_KEY")
ABUSE_API_KEY = os.getenv("ABUSE_API_KEY")
GREYNOISE_API_KEY = os.getenv("GREYNOISE_API_KEY")
OTX_API_KEY = os.getenv("OTX_API_KEY")
THREATFOX_API_KEY = os.getenv("THREATFOX_API_KEY")

TIMEOUT = 5
TIMEOUT_OTX = 30
timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")

# =========================
# COLOR
# =========================
class Color:
    RED = "\033[91m"
    GREEN = "\033[92m"
    YELLOW = "\033[93m"
    BLUE = "\033[94m"
    CYAN = "\033[96m"
    BOLD = "\033[1m"
    RESET = "\033[0m"


# =========================
# DETECT TYPE
# =========================
def detect_type(value):
    try:
        ipaddress.ip_address(value)
        return "ip"
    except:
        pass

    if re.fullmatch(r"[a-fA-F0-9]{32}", value) or \
       re.fullmatch(r"[a-fA-F0-9]{40}", value) or \
       re.fullmatch(r"[a-fA-F0-9]{64}", value):
        return "hash"

    if re.fullmatch(r"(?!\-)(?:[a-zA-Z0-9\-]{1,63}\.)+[a-zA-Z]{2,}", value):
        return "domain"

    return None


# =========================
# INPUT
# =========================
def get_user_inputs(max_items=4):
    raw = input(f"Max {max_items} IOC (IP/Domain/Hash) - Delimitter (,) no space:\n> ")

    items = [x.strip() for x in raw.split(",") if x.strip()]

    if len(items) > max_items:
        print(f"[!] Max {max_items}, rest ignored")
        items = items[:max_items]

    results = []

    for item in items:
        t = detect_type(item)
        if not t:
            print(f"[!] Invalid skipped: {item}")
            continue

        results.append((t, item))

    return results


# =========================
# IP ENGINE
# =========================
def check_virustotal_ip(ip):
    try:
        url = f"https://www.virustotal.com/api/v3/ip_addresses/{ip}"
        headers = {"x-apikey": VT_API_KEY}

        r = requests.get(url, headers=headers, timeout=TIMEOUT)
        if r.status_code != 200:
            return {"error": True}

        data = r.json()
        attr = data.get("data", {}).get("attributes", {})
        stats = attr.get("last_analysis_stats", {})

        return {
            "malicious": stats.get("malicious", 0),
            "asn": attr.get("asn"),
            "as_owner": attr.get("as_owner")
        }
    except:
        return {"error": True}


def check_abuseipdb(ip):
    try:
        url = "https://api.abuseipdb.com/api/v2/check"
        headers = {"Key": ABUSE_API_KEY, "Accept": "application/json"}
        params = {"ipAddress": ip}

        r = requests.get(url, headers=headers, params=params, timeout=TIMEOUT)
        if r.status_code != 200:
            return {"error": True}

        data = r.json().get("data", {})

        return {
            "score": data.get("abuseConfidenceScore"),
            "isp": data.get("isp"),
            "usage": data.get("usageType")
        }
    except:
        return {"error": True}


def check_greynoise(ip):
    try:
        url = f"https://api.greynoise.io/v3/community/{ip}"
        headers = {"key": GREYNOISE_API_KEY}

        r = requests.get(url, headers=headers, timeout=TIMEOUT)

        if r.status_code == 404:
            return {"classification": "unknown"}

        data = r.json()

        return {
            "classification": data.get("classification"),
            "noise": data.get("noise"),
            "riot": data.get("riot")
        }
    except:
        return {"error": True}


def check_otx_ip(ip):
    try:
        url = f"https://otx.alienvault.com/api/v1/indicators/IPv4/{ip}/general"
        headers = {"X-OTX-API-KEY": OTX_API_KEY}

        r = requests.get(url, headers=headers, timeout=TIMEOUT_OTX)
        if r.status_code != 200:
            return {
                "error": True,
                "status_code": r.status_code,
                "response": r.text
            }

        return {"pulse_count": r.json().get("pulse_info", {}).get("count", 0)}
    except Exception as e:
        return {
            "error": True,
            "message": str(e)
        }


def check_threatfox_ip(ip):
    try:
        url = "https://threatfox-api.abuse.ch/api/v1/"
        headers = {"Auth-Key": THREATFOX_API_KEY, "Content-Type": "application/json"}

        payload = {"query": "search_ioc", "search_term": ip}

        r = requests.post(url, json=payload, headers=headers, timeout=TIMEOUT)
        data = r.json()

        if data.get("query_status") != "ok":
            return {"found": False}
        
        results = data.get("data", [])
        ioc = results[0]
        return {
            "found": True,
            "threat_type": ioc.get("threat_type"),
            "malware": ioc.get("malware"),
            "malware_alias": ioc.get("malware_alias"),
            "confidence": ioc.get("confidence_level")
        }
    except:
        return {"error": True}


# =========================
# DOMAIN ENGINE
# =========================

# =========================
# DOMAIN AGE FUNCTION
# =========================
def extract_domain_age_from_vt(vt_attributes):
    try:
        whois_text = vt_attributes.get("whois", "")

        if not whois_text:
            return {
                "age_days": None,
                "creation_date": None,
                "error": "whois_not_found"
            }

        patterns = [
            r"Creation Date:\s*(.*)",
            r"Created On:\s*(.*)",
            r"Registered On:\s*(.*)",
            r"Created:\s*(.*)",
            r"Create date:\s*(.*)"
        ]

        raw_date = None

        for p in patterns:
            match = re.search(p, whois_text, re.IGNORECASE)
            if match:
                raw_date = match.group(1).strip()
                break

        if not raw_date:
            return {
                "age_days": None,
                "creation_date": None,
                "error": "creation_date_not_found"
            }

        try:
            date_str = raw_date[:10]
            creation_dt = datetime.strptime(date_str, "%Y-%m-%d")
        except:
            return {
                "age_days": None,
                "creation_date": raw_date,
                "error": "date_parse_failed"
            }

        age_days = (datetime.now() - creation_dt).days

        return {
            "age_days": age_days,
            "creation_date": creation_dt.strftime("%Y-%m-%d"),
            "error": None
        }

    except Exception as e:
        return {
            "age_days": None,
            "creation_date": None,
            "error": str(e)
        }



def check_vt_domain(domain):
    try:
        url = f"https://www.virustotal.com/api/v3/domains/{domain}"
        headers = {"x-apikey": VT_API_KEY}

        r = requests.get(url, headers=headers, timeout=TIMEOUT)
        if r.status_code != 200:
            return {"error": True}

        data = r.json()
        attr = data.get("data", {}).get("attributes", {})

        # DOMAIN AGE
        age_info = extract_domain_age_from_vt(attr)

        stats = r.json().get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
        return {
            "malicious": stats.get("malicious", 0),
            "domain": domain,
            "age_days": age_info.get("age_days"),
            "creation_date": age_info.get("creation_date"),
            "error": age_info.get("error")
            }
    except:
        return {"error": True}


def check_otx_domain(domain):
    try:
        url = f"https://otx.alienvault.com/api/v1/indicators/domain/{domain}/general"
        headers = {"X-OTX-API-KEY": OTX_API_KEY}

        r = requests.get(url, headers=headers, timeout=TIMEOUT_OTX)
        if r.status_code != 200:
            return {
                "error": True,
                "status_code": r.status_code,
                "response": r.text
            }

        return {"pulse_count": r.json().get("pulse_info", {}).get("count", 0)}
    except Exception as e:
        return {
            "error": True,
            "message": str(e)
        }

def check_threatfox_domain(domain):
    try:
        url = "https://threatfox-api.abuse.ch/api/v1/"
        headers = {"Auth-Key": THREATFOX_API_KEY, "Content-Type": "application/json"}

        payload = {"query": "search_ioc", "search_term": domain, "exact_match": True}

        r = requests.post(url, json=payload, headers=headers, timeout=TIMEOUT)
        data = r.json()

        if data.get("query_status") != "ok":
            return {"found": False}
        
        results = data.get("data", [])
        ioc = results[0]
        return {
            "found": True,
            "threat_type": ioc.get("threat_type"),
            "malware": ioc.get("malware"),
            "malware_alias": ioc.get("malware_alias"),
            "confidence": ioc.get("confidence_level")
        }
    except:
        return {"error": True}
# =========================
# HASH ENGINE
# =========================
def check_vt_hash(hash_value):
    try:
        url = f"https://www.virustotal.com/api/v3/files/{hash_value}"
        headers = {"x-apikey": VT_API_KEY}

        r = requests.get(url, headers=headers, timeout=TIMEOUT)
        if r.status_code != 200:
            return {"error": True}

        stats = r.json().get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
        return {"malicious": stats.get("malicious", 0)}
    except:
        return {"error": True}


def check_otx_hash(hash_value):
    try:
        url = f"https://otx.alienvault.com/api/v1/indicators/file/{hash_value}/general"
        headers = {"X-OTX-API-KEY": OTX_API_KEY}

        r = requests.get(url, headers=headers, timeout=TIMEOUT_OTX)
        if r.status_code != 200:
            return {
                "error": True,
                "status_code": r.status_code,
                "response": r.text
            }

        return {"pulse_count": r.json().get("pulse_info", {}).get("count", 0)}
    except Exception as e:
        return {
            "error": True,
            "message": str(e)
        }


def check_threatfox_hash(hash_value):
    try:
        url = "https://threatfox-api.abuse.ch/api/v1/"
        headers = {"Auth-Key": THREATFOX_API_KEY, "Content-Type": "application/json"}

        payload = {"query": "search_hash", "hash": hash_value}

        r = requests.post(url, json=payload, headers=headers, timeout=TIMEOUT)
        data = r.json()

        if data.get("query_status") != "ok":
            return {"found": False}
        
        results = data.get("data", [])
        ioc = results[0]
        return {
            "found": True,
            "threat_type": ioc.get("threat_type"),
            "malware": ioc.get("malware"),
            "malware_alias": ioc.get("malware_alias"),
            "confidence": ioc.get("confidence_level")
        }
    except:
        return {"error": True}


# =========================
# ENRICH
# =========================
def enrich_item(t, v):
    if t == "ip":
        with ThreadPoolExecutor(max_workers=5) as ex:
            return {
                "type": "ip",
                "value": v,
                "virustotal": ex.submit(check_virustotal_ip, v).result(),
                "abuseipdb": ex.submit(check_abuseipdb, v).result(),
                "greynoise": ex.submit(check_greynoise, v).result(),
                "otx": ex.submit(check_otx_ip, v).result(),
                "threatfox": ex.submit(check_threatfox_ip, v).result()
            }

    if t == "domain":
        return {
            "type": "domain",
            "value": v,
            "virustotal": check_vt_domain(v),
            "otx": check_otx_domain(v),
            "threatfox": check_threatfox_domain(v)
        }

    if t == "hash":
        return {
            "type": "hash",
            "value": v,
            "virustotal": check_vt_hash(v),
            "otx": check_otx_hash(v),
            "threatfox": check_threatfox_hash(v)
        }


# =========================
# BULK
# =========================
def bulk_check(items):
    results = []

    print(f"\n[+] Processing {len(items)} IOC(s)...\n")

    with ThreadPoolExecutor(max_workers=5) as executor:
        futures = {
            executor.submit(enrich_item, t, v): (t, v)
            for t, v in items
        }

        for i, future in enumerate(as_completed(futures), 1):
            t, v = futures[future]
            print(f"[>] ({i}/{len(items)}) {v} ({t})")
            results.append(future.result())

    return results

# =========================
# CALCULATE RISK
# =========================
def calculate_risk_hash(data):
    score = 0

    vt = data.get("virustotal", {})
    otx = data.get("otx", {})
    tf = data.get("threatfox", {})

    # =========================
    # VT (MAX 60)
    # =========================
    vt_mal = vt.get("malicious", 0)

    if vt_mal > 0:
        score += min(60, 10 + vt_mal * 3)

    # =========================
    # ThreatFox (MAX 30)
    # =========================
    if tf.get("found"):
        confidence = tf.get("confidence") or 50
        score += min(30, 10 + confidence * 0.4)

    # =========================
    # OTX (MAX 10)
    # =========================
    score += min(10, (otx.get("pulse_count") or 0) * 2)

    return min(100, score)


def calculate_risk_ip(data):
    score = 0

    vt = data.get("virustotal", {})
    abuse = data.get("abuseipdb", {})
    gn = data.get("greynoise", {})
    otx = data.get("otx", {})
    tf = data.get("threatfox", {})

    # =========================
    # VT (MAX 40)
    # =========================
    vt_mal = vt.get("malicious", 0)
    score += min(40, vt_mal * 10)

    # =========================
    # ThreatFox (MAX 25)
    # =========================
    if tf.get("found"):
        score += 25

    # =========================
    # AbuseIPDB (MAX 25)
    # =========================
    abuse_score = abuse.get("score") or 0
    score += min(25, abuse_score * 0.25)

    # =========================
    # OTX (MAX 10)
    # =========================
    score += min(10, (otx.get("pulse_count") or 0) * 2)

    # =========================
    # GreyNoise (CRITICAL)
    # =========================
    if gn.get("classification") == "malicious":
        score += 15

    if gn.get("noise"):
        score += 10

    if gn.get("riot"):
        score -= 10 

    # =========================
    # Infra Context
    # =========================
    isp = (abuse.get("isp") or "").lower()
    usage = (abuse.get("usage") or "").lower()

    if not any(x in isp for x in ["google", "amazon"]):
        score += 5
    if any(x in usage for x in ["data center", "hosting", "transit"]):
        score += 5
    return max(0, min(100, score))


def tld_risk_score(domain):
    HIGH_RISK_TLDS = [".xyz", ".top", ".click", ".work", ".ru"]
    LOW_RISK_TLDS = [".gov", ".mil", ".edu",
        ".jp", ".de", ".ch", ".nl", ".no", ".se",
        ".com", ".org", ".net", ".co", ".co.id", ".go.id", ".mil.id"]
    domain = domain.lower()

    if any(domain.endswith(t) for t in HIGH_RISK_TLDS):
        return 8
    if not any(domain.endswith(t) for t in LOW_RISK_TLDS):
        return 4

    return 0

def calculate_risk_domain(data):
    score = 0

    vt = data.get("virustotal", {})
    otx = data.get("otx", {})
    tf = data.get("threatfox", {})

    # =========================
    # VT (MAX 50)
    # =========================
    vt_mal = vt.get("malicious", 0)
    score += min(50, vt_mal * 15)

    # =========================
    # ThreatFox (MAX 40)
    # =========================
    if tf.get("found"):
        score += 40

    # =========================
    # OTX (MAX 10)
    # =========================
    score += min(10, (otx.get("pulse_count") or 0) * 2)

    # =========================
    # Domain penalty (default lower trust)
    # =========================
    if vt_mal == 0 and not tf.get("found"):
        score -= 10

    # =========================
    # Domain Age
    # =========================
    age = vt.get("age_days")

    if vt_mal > 1 and age is not None:
        if age < 30:
            score += 25
        elif age < 90:
            score += 20
        elif age < 180:
            score += 10
        elif age < 365:
            score += 5
        else:
            score -= 5

    # =========================
    # Domain TLD Risk
    # =========================
    tld_risk = tld_risk_score(vt.get("domain"))
    score += tld_risk

    return max(0, min(100, score))


def calculate_risk(data):
    t = data.get("type")

    if t == "ip":
        return calculate_risk_ip(data)

    elif t == "domain":
        return calculate_risk_domain(data)

    elif t == "hash":
        return calculate_risk_hash(data)

    return 0


# =========================
# OUTPUT
# =========================
def format_output(data):
    t = data.get("type")
    v = data.get("value")

    vt = data.get("virustotal", {})
    otx = data.get("otx", {})
    tf = data.get("threatfox", {})

    risk = calculate_risk(data)

    if risk >= 70:
        level = "HIGH"
        color = Color.RED
    elif risk >= 30:
        level = "MEDIUM"
        color = Color.YELLOW
    else:
        level = "LOW"
        color = Color.GREEN

    output = f"""
{Color.BOLD}========================================{Color.RESET}
TYPE        : {Color.CYAN}{t.upper()}{Color.RESET}
VALUE       : {v}
RISK SCORE  : {color}{risk}{Color.RESET}
RISK LEVEL  : {color}{level}{Color.RESET}
{Color.BOLD}========================================{Color.RESET}
"""

    # =========================
    # VIRUSTOTAL
    # =========================
    output += f"""
{Color.BLUE}[VirusTotal]{Color.RESET}
- Malicious      : {vt.get("malicious")}
- Suspicious     : {vt.get("suspicious")}
"""

    # =========================
    # OTX
    # =========================
    output += f"""
{Color.BLUE}[OTX]{Color.RESET}
- Pulse Count    : {otx.get("pulse_count")}
- Reputation     : {otx.get("reputation")}
"""

    # =========================
    # THREATFOX
    # =========================
    tf_found = tf.get("found")
    tf_color = Color.RED if tf_found else Color.GREEN

    output += f"""
{Color.BLUE}[ThreatFox]{Color.RESET}
- Found          : {tf_color}{tf_found}{Color.RESET}
- Threat Type    : {tf.get("threat_type")}
- Malware        : {tf.get("malware")}
- Malware Alias  : {tf.get("malware_alias")}
- Confidence     : {tf.get("confidence")}
"""

    # =========================
    # IP EXTRA
    # =========================
    if t == "ip":
        abuse = data.get("abuseipdb", {})
        gn = data.get("greynoise", {})
        vt_ip = data.get("virustotal", {})

        noise_color = Color.YELLOW if gn.get("noise") else Color.GREEN
        riot_color = Color.GREEN if gn.get("riot") else Color.RED

        output += f"""
{Color.BLUE}[AbuseIPDB]{Color.RESET}
- Score          : {abuse.get("score")}
- ISP            : {abuse.get("isp")}
- Usage          : {abuse.get("usage")}

{Color.BLUE}[GreyNoise]{Color.RESET}
- Classification : {gn.get("classification")}
- Noise          : {noise_color}{gn.get("noise")}{Color.RESET}
- RIOT           : {riot_color}{gn.get("riot")}{Color.RESET}

{Color.BLUE}[Network]{Color.RESET}
- ASN            : {vt_ip.get("asn")}
- Owner          : {vt_ip.get("as_owner")}
"""

    # =========================
    # Domain EXTRA
    # =========================
    if t == "domain":
        output += f"""
========================================
DOMAIN AGE (days)    : {vt.get("age_days")}
CREATED DATE  : {vt.get("creation_date")}
========================================
        """
    output += f"\n{Color.BOLD}----------------------------------------{Color.RESET}\n"

    return output

# =========================
# SUMMARY
# =========================
def build_summary(results):
    total = len(results)

    high = 0
    medium = 0
    low = 0

    for r in results:
        risk = calculate_risk(r)

        if risk >= 70:
            high += 1
        elif risk >= 30:
            medium += 1
        else:
            low += 1

    return f"""
{Color.BOLD}======================{Color.RESET}
{Color.BOLD}SUMMARY{Color.RESET}
{Color.BOLD}======================{Color.RESET}
Total IOC   : {total}
High Risk   : {Color.RED}{high}{Color.RESET}
Medium Risk : {Color.YELLOW}{medium}{Color.RESET}
Low Risk    : {Color.GREEN}{low}{Color.RESET}
{Color.BOLD}======================{Color.RESET}
"""


# =========================
# MAIN
# =========================
if __name__ == "__main__":
    items = get_user_inputs()

    if not items:
        print("No valid IOC")
        exit()

    results = bulk_check(items)
    # filename = f"debug_{timestamp}.json"
    # with open(filename, "w") as f:
    #     json.dump(results, f, indent=2)

    # print(f"\n[+] Raw data saved to debug_{timestamp}.json\n")

    print(build_summary(results))
    print("\nDETAIL\n")
    for r in results:
        print(format_output(r))
