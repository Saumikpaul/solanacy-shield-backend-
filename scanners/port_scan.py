"""
Port Scanner
=============
Scans for open ports on the target domain using python-nmap.
Identifies dangerous or unexpected exposed services.

Checks:
  - Common web/service ports
  - Dangerous ports (Telnet, FTP, RDP, etc.)
  - Port banners for version info leakage
"""

import logging
from typing import Dict, Any

logger = logging.getLogger(__name__)

CRITICAL = "critical"
HIGH     = "high"
MEDIUM   = "medium"
LOW      = "low"
INFO     = "info"

# Ports that should almost never be open on a web server
DANGEROUS_PORTS = {
    21:   {"name": "FTP",         "severity": HIGH,     "reason": "FTP transmits data and credentials in plaintext."},
    23:   {"name": "Telnet",      "severity": CRITICAL, "reason": "Telnet is completely unencrypted. Never expose this."},
    25:   {"name": "SMTP",        "severity": MEDIUM,   "reason": "Open SMTP can be abused for spam relaying."},
    3306: {"name": "MySQL",       "severity": CRITICAL, "reason": "Database port exposed to the internet. Extreme risk."},
    5432: {"name": "PostgreSQL",  "severity": CRITICAL, "reason": "Database port exposed to the internet. Extreme risk."},
    6379: {"name": "Redis",       "severity": CRITICAL, "reason": "Redis exposed without auth leads to full data access."},
    27017:{"name": "MongoDB",     "severity": CRITICAL, "reason": "MongoDB exposed to internet. High data breach risk."},
    3389: {"name": "RDP",         "severity": HIGH,     "reason": "RDP exposed to internet is a common attack vector."},
    5900: {"name": "VNC",         "severity": HIGH,     "reason": "VNC exposed to internet is a serious security risk."},
    8080: {"name": "HTTP-Alt",    "severity": MEDIUM,   "reason": "Alternative HTTP port often runs dev/admin interfaces."},
    8443: {"name": "HTTPS-Alt",   "severity": LOW,      "reason": "Alternative HTTPS port — verify if intentional."},
    9200: {"name": "Elasticsearch","severity": CRITICAL,"reason": "Elasticsearch exposed without auth leaks all data."},
    11211:{"name": "Memcached",   "severity": HIGH,     "reason": "Memcached exposed is a common DDoS amplification target."},
}

# Common ports to scan
SCAN_PORTS = "21,22,23,25,80,443,3306,3389,5432,5900,6379,8080,8443,9200,11211,27017"


def check_ports(domain: str) -> Dict[str, Any]:
    """
    Scan the target for open ports and flag dangerous ones.
    Uses nmap with a fast, non-aggressive scan profile.
    """
    issues         = []
    score_deduction = 0
    open_ports     = []

    # Strip protocol/path
    clean_domain = domain.replace("https://", "").replace("http://", "").split("/")[0]

    try:
        import nmap
        nm = nmap.PortScanner()
    except ImportError:
        logger.error("python-nmap not installed or nmap binary missing")
        return _build_result([{
            "title":          "Port Scanner Unavailable",
            "severity":       INFO,
            "description":    "nmap is not available on this server.",
            "recommendation": "Install nmap to enable port scanning."
        }], 0, [])

    try:
        logger.info(f"Starting port scan on {clean_domain}")
        # -sV: version detection, -T3: normal timing, -Pn: skip ping (works on servers that block ICMP)
        nm.scan(
            hosts=clean_domain,
            ports=SCAN_PORTS,
            arguments="-sV -T3 -Pn --open"
        )
    except nmap.PortScannerError as e:
        logger.error(f"nmap scan error: {e}")
        return _build_result([{
            "title":          "Port Scan Failed",
            "severity":       INFO,
            "description":    f"nmap scan could not complete: {str(e)}",
            "recommendation": "Ensure nmap is installed and the target is reachable."
        }], 0, [])
    except Exception as e:
        logger.error(f"Unexpected error during port scan: {e}")
        return _build_result([{
            "title":          "Port Scan Error",
            "severity":       INFO,
            "description":    str(e),
            "recommendation": "Check server logs for details."
        }], 0, [])

    # ── Parse scan results ────────────────────────────────────────────
    for host in nm.all_hosts():
        for proto in nm[host].all_protocols():
            port_list = nm[host][proto].keys()
            for port in sorted(port_list):
                state   = nm[host][proto][port]["state"]
                service = nm[host][proto][port].get("name", "unknown")
                version = nm[host][proto][port].get("version", "")
                product = nm[host][proto][port].get("product", "")

                if state != "open":
                    continue

                port_info = {
                    "port":    port,
                    "service": service,
                    "version": f"{product} {version}".strip(),
                    "state":   state
                }
                open_ports.append(port_info)

                # ── Flag dangerous ports ──────────────────────────────
                if port in DANGEROUS_PORTS:
                    danger  = DANGEROUS_PORTS[port]
                    deduct  = {"critical": 30, "high": 20, "medium": 10, "low": 5}.get(danger["severity"], 10)
                    issues.append({
                        "title":          f"Dangerous Port Open: {port}/{danger['name']}",
                        "severity":       danger["severity"],
                        "description":    f"Port {port} ({danger['name']}) is open. {danger['reason']}",
                        "recommendation": f"Close port {port} in your firewall unless absolutely required. If needed, restrict access by IP whitelist.",
                        "port":           port
                    })
                    score_deduction += deduct

                # ── Flag version info leakage ─────────────────────────
                if version and port not in [80, 443]:
                    issues.append({
                        "title":          f"Service Version Exposed on Port {port}",
                        "severity":       LOW,
                        "description":    f"Port {port} is advertising version info: '{product} {version}'. This helps attackers find known CVEs.",
                        "recommendation": "Configure your services to suppress version banners.",
                        "port":           port
                    })
                    score_deduction += 3

    if not open_ports:
        issues.append({
            "title":          "No Dangerous Ports Detected",
            "severity":       INFO,
            "description":    "Scanned common ports — no unexpected open ports found.",
            "recommendation": "Regularly re-scan after infrastructure changes."
        })
    elif not issues:
        issues.append({
            "title":          f"{len(open_ports)} Open Port(s) Found — No Critical Issues",
            "severity":       INFO,
            "description":    f"Found {len(open_ports)} open ports, none critically dangerous.",
            "recommendation": "Review open ports periodically to ensure they are all intentional."
        })

    return _build_result(issues, score_deduction, open_ports)


def _build_result(issues: list, score_deduction: int, open_ports: list) -> Dict[str, Any]:
    return {
        "scanner":         "ports",
        "issues":          issues,
        "score_deduction": min(score_deduction, 100),
        "details":         {"open_ports": open_ports}
    }
