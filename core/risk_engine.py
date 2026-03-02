"""
Risk Classification Engine
Analyzes parsed nmap data and assigns severity levels.
"""


# Common risky ports and reasoning
RISKY_PORTS = {
    "21": ("HIGH", "FTP can allow anonymous access or credential brute force."),
    "22": ("MEDIUM", "SSH exposed to internet may allow brute force attacks."),
    "23": ("CRITICAL", "Telnet transmits data in plaintext and is highly insecure."),
    "25": ("LOW", "SMTP can be abused for spam or mail relay if misconfigured."),
    "53": ("MEDIUM", "DNS exposed publicly may allow amplification attacks."),
    "80": ("INFO", "HTTP service detected. Check for outdated web server."),
    "110": ("MEDIUM", "POP3 may expose credentials if not encrypted."),
    "139": ("HIGH", "NetBIOS exposure may allow enumeration."),
    "443": ("INFO", "HTTPS service detected. Check certificate and TLS config."),
    "445": ("CRITICAL", "SMB exposed. Often targeted by ransomware and exploits."),
    "3389": ("CRITICAL", "RDP exposed. High brute-force and exploit risk."),
}


def classify_ports(parsed_ports):
    """
    Takes list of parsed open ports.
    Returns list of classified findings.
    """

    findings = []

    for port in parsed_ports:
        port_id = port["port"]
        service = port["service"]
        version = port["version"]

        # Default values
        severity = "UNKNOWN"
        reason = "No specific risk rule defined."

        if port_id in RISKY_PORTS:
            severity, reason = RISKY_PORTS[port_id]

        findings.append({
            "port": port_id,
            "protocol": port["protocol"],
            "service": service,
            "version": version,
            "severity": severity,
            "reason": reason
        })

    return findings
