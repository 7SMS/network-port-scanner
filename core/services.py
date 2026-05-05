"""
Service signature database.

This is intentionally small and pragmatic. Real service detection (à la nmap-services)
uses thousands of probes — we cover the common ones. Don't pretend this is exhaustive.
"""

# Map of port -> (service_name, default_protocol)
# Sourced from IANA / common operational defaults.
COMMON_PORTS = {
    21: ("ftp", "tcp"),
    22: ("ssh", "tcp"),
    23: ("telnet", "tcp"),
    25: ("smtp", "tcp"),
    53: ("dns", "tcp/udp"),
    67: ("dhcp-server", "udp"),
    68: ("dhcp-client", "udp"),
    69: ("tftp", "udp"),
    80: ("http", "tcp"),
    110: ("pop3", "tcp"),
    111: ("rpcbind", "tcp/udp"),
    119: ("nntp", "tcp"),
    123: ("ntp", "udp"),
    135: ("msrpc", "tcp"),
    137: ("netbios-ns", "udp"),
    138: ("netbios-dgm", "udp"),
    139: ("netbios-ssn", "tcp"),
    143: ("imap", "tcp"),
    161: ("snmp", "udp"),
    162: ("snmptrap", "udp"),
    389: ("ldap", "tcp"),
    443: ("https", "tcp"),
    445: ("smb", "tcp"),
    465: ("smtps", "tcp"),
    514: ("syslog", "udp"),
    515: ("printer", "tcp"),
    548: ("afp", "tcp"),
    587: ("submission", "tcp"),
    631: ("ipp", "tcp"),
    636: ("ldaps", "tcp"),
    873: ("rsync", "tcp"),
    993: ("imaps", "tcp"),
    995: ("pop3s", "tcp"),
    1080: ("socks", "tcp"),
    1194: ("openvpn", "udp"),
    1433: ("mssql", "tcp"),
    1521: ("oracle", "tcp"),
    1723: ("pptp", "tcp"),
    2049: ("nfs", "tcp"),
    2222: ("ssh-alt", "tcp"),
    2375: ("docker", "tcp"),
    2376: ("docker-tls", "tcp"),
    3000: ("http-dev", "tcp"),
    3306: ("mysql", "tcp"),
    3389: ("rdp", "tcp"),
    4444: ("metasploit", "tcp"),
    5000: ("upnp/http-dev", "tcp"),
    5432: ("postgresql", "tcp"),
    5500: ("vnc-listen", "tcp"),
    5601: ("kibana", "tcp"),
    5672: ("amqp", "tcp"),
    5900: ("vnc", "tcp"),
    5984: ("couchdb", "tcp"),
    6379: ("redis", "tcp"),
    6667: ("irc", "tcp"),
    7474: ("neo4j", "tcp"),
    8000: ("http-alt", "tcp"),
    8008: ("http-alt", "tcp"),
    8080: ("http-proxy", "tcp"),
    8081: ("http-alt", "tcp"),
    8443: ("https-alt", "tcp"),
    8888: ("http-alt", "tcp"),
    9000: ("php-fpm/sonar", "tcp"),
    9092: ("kafka", "tcp"),
    9200: ("elasticsearch", "tcp"),
    9300: ("elasticsearch-cluster", "tcp"),
    11211: ("memcached", "tcp"),
    27017: ("mongodb", "tcp"),
    27018: ("mongodb-shard", "tcp"),
    50000: ("sap", "tcp"),
}


def lookup_service(port: int, protocol: str = "tcp") -> str:
    """Return the canonical service name for a port, or 'unknown'."""
    entry = COMMON_PORTS.get(port)
    if entry is None:
        return "unknown"
    name, _ = entry
    return name


# Probes that elicit a banner from common services.
# Format: bytes_to_send (or b"" for passive — just connect and read)
SERVICE_PROBES = {
    "http": b"GET / HTTP/1.0\r\nHost: localhost\r\nUser-Agent: Mozilla/5.0\r\n\r\n",
    "https": b"",  # TLS — handled separately
    "ssh": b"",    # SSH banner is sent by server on connect
    "ftp": b"",    # FTP greets on connect
    "smtp": b"",   # SMTP greets on connect
    "pop3": b"",
    "imap": b"",
    "telnet": b"",
    "redis": b"PING\r\n",
    "memcached": b"version\r\n",
    "mysql": b"",  # MySQL sends greeting first
    "mongodb": b"",
    "vnc": b"",    # RFB greets on connect
}


def get_probe(service: str) -> bytes:
    """Get the appropriate probe bytes for a known service."""
    return SERVICE_PROBES.get(service, b"")
