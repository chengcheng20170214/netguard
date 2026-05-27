
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from app.models.models import KnownService

KNOWN_SERVICES = [
    {"port": 21, "proto": "tcp", "name": "FTP", "category": "file_transfer", "risk": "high", "description": "File Transfer Protocol"},
    {"port": 22, "proto": "tcp", "name": "SSH", "category": "remote_access", "risk": "critical", "description": "Secure Shell"},
    {"port": 23, "proto": "tcp", "name": "Telnet", "category": "remote_access", "risk": "critical", "description": "Telnet remote login"},
    {"port": 25, "proto": "tcp", "name": "SMTP", "category": "mail", "risk": "medium", "description": "Simple Mail Transfer Protocol"},
    {"port": 53, "proto": "tcp", "name": "DNS", "category": "infrastructure", "risk": "medium", "description": "Domain Name System"},
    {"port": 80, "proto": "tcp", "name": "HTTP", "category": "web", "risk": "medium", "description": "Hypertext Transfer Protocol"},
    {"port": 110, "proto": "tcp", "name": "POP3", "category": "mail", "risk": "low", "description": "Post Office Protocol v3"},
    {"port": 111, "proto": "tcp", "name": "RPCBind", "category": "infrastructure", "risk": "high", "description": "RPC Bind Service"},
    {"port": 135, "proto": "tcp", "name": "MSRPC", "category": "remote_access", "risk": "high", "description": "Microsoft RPC"},
    {"port": 139, "proto": "tcp", "name": "NetBIOS", "category": "file_transfer", "risk": "high", "description": "NetBIOS Session Service"},
    {"port": 143, "proto": "tcp", "name": "IMAP", "category": "mail", "risk": "low", "description": "Internet Message Access Protocol"},
    {"port": 161, "proto": "udp", "name": "SNMP", "category": "monitoring", "risk": "critical", "description": "Simple Network Management Protocol"},
    {"port": 389, "proto": "tcp", "name": "LDAP", "category": "infrastructure", "risk": "high", "description": "Lightweight Directory Access Protocol"},
    {"port": 443, "proto": "tcp", "name": "HTTPS", "category": "web", "risk": "medium", "description": "HTTP over TLS/SSL"},
    {"port": 445, "proto": "tcp", "name": "SMB", "category": "file_transfer", "risk": "critical", "description": "Server Message Block"},
    {"port": 465, "proto": "tcp", "name": "SMTPS", "category": "mail", "risk": "low", "description": "SMTP over SSL"},
    {"port": 514, "proto": "tcp", "name": "Syslog", "category": "monitoring", "risk": "medium", "description": "Syslog Service"},
    {"port": 548, "proto": "tcp", "name": "AFP", "category": "file_transfer", "risk": "medium", "description": "Apple Filing Protocol"},
    {"port": 554, "proto": "tcp", "name": "RTSP", "category": "streaming", "risk": "medium", "description": "Real Time Streaming Protocol"},
    {"port": 587, "proto": "tcp", "name": "SMTP-Submission", "category": "mail", "risk": "medium", "description": "SMTP Message Submission"},
    {"port": 636, "proto": "tcp", "name": "LDAPS", "category": "infrastructure", "risk": "medium", "description": "LDAP over SSL"},
    {"port": 873, "proto": "tcp", "name": "Rsync", "category": "file_transfer", "risk": "medium", "description": "Rsync File Synchronization"},
    {"port": 902, "proto": "tcp", "name": "VMware Auth", "category": "remote_access", "risk": "high", "description": "VMware Authentication Daemon"},
    {"port": 993, "proto": "tcp", "name": "IMAPS", "category": "mail", "risk": "low", "description": "IMAP over SSL"},
    {"port": 995, "proto": "tcp", "name": "POP3S", "category": "mail", "risk": "low", "description": "POP3 over SSL"},
    {"port": 1080, "proto": "tcp", "name": "SOCKS", "category": "proxy", "risk": "high", "description": "SOCKS Proxy"},
    {"port": 1433, "proto": "tcp", "name": "MSSQL", "category": "database", "risk": "critical", "description": "Microsoft SQL Server"},
    {"port": 1434, "proto": "udp", "name": "MSSQL Browser", "category": "database", "risk": "high", "description": "MSSQL Browser Service"},
    {"port": 1521, "proto": "tcp", "name": "Oracle DB", "category": "database", "risk": "critical", "description": "Oracle Database Listener"},
    {"port": 2049, "proto": "tcp", "name": "NFS", "category": "file_transfer", "risk": "high", "description": "Network File System"},
    {"port": 2181, "proto": "tcp", "name": "ZooKeeper", "category": "infrastructure", "risk": "medium", "description": "Apache ZooKeeper"},
    {"port": 2375, "proto": "tcp", "name": "Docker API", "category": "infrastructure", "risk": "critical", "description": "Docker Remote API (unencrypted)"},
    {"port": 2376, "proto": "tcp", "name": "Docker API TLS", "category": "infrastructure", "risk": "high", "description": "Docker Remote API (TLS)"},
    {"port": 3000, "proto": "tcp", "name": "Dev Server", "category": "web", "risk": "medium", "description": "Development Web Server"},
    {"port": 3306, "proto": "tcp", "name": "MySQL", "category": "database", "risk": "critical", "description": "MySQL Database"},
    {"port": 3389, "proto": "tcp", "name": "RDP", "category": "remote_access", "risk": "critical", "description": "Remote Desktop Protocol"},
    {"port": 4369, "proto": "tcp", "name": "EPMD", "category": "messaging", "risk": "medium", "description": "Erlang Port Mapper Daemon"},
    {"port": 5432, "proto": "tcp", "name": "PostgreSQL", "category": "database", "risk": "critical", "description": "PostgreSQL Database"},
    {"port": 5672, "proto": "tcp", "name": "AMQP", "category": "messaging", "risk": "medium", "description": "Advanced Message Queuing Protocol"},
    {"port": 5900, "proto": "tcp", "name": "VNC", "category": "remote_access", "risk": "critical", "description": "Virtual Network Computing"},
    {"port": 5984, "proto": "tcp", "name": "CouchDB", "category": "database", "risk": "high", "description": "Apache CouchDB"},
    {"port": 6379, "proto": "tcp", "name": "Redis", "category": "database", "risk": "critical", "description": "Redis In-Memory Data Store"},
    {"port": 6443, "proto": "tcp", "name": "Kubernetes API", "category": "infrastructure", "risk": "critical", "description": "Kubernetes API Server"},
    {"port": 7001, "proto": "tcp", "name": "WebLogic", "category": "web", "risk": "critical", "description": "Oracle WebLogic Server"},
    {"port": 8000, "proto": "tcp", "name": "HTTP Alt", "category": "web", "risk": "medium", "description": "Alternate HTTP Service"},
    {"port": 8080, "proto": "tcp", "name": "HTTP Proxy", "category": "web", "risk": "medium", "description": "HTTP Proxy / Alternate Web"},
    {"port": 8443, "proto": "tcp", "name": "HTTPS Alt", "category": "web", "risk": "medium", "description": "Alternate HTTPS Service"},
    {"port": 8888, "proto": "tcp", "name": "HTTP Alt", "category": "web", "risk": "medium", "description": "Alternate HTTP Service"},
    {"port": 9090, "proto": "tcp", "name": "Prometheus", "category": "monitoring", "risk": "medium", "description": "Prometheus Monitoring"},
    {"port": 9200, "proto": "tcp", "name": "Elasticsearch", "category": "database", "risk": "high", "description": "Elasticsearch HTTP"},
    {"port": 9300, "proto": "tcp", "name": "ES Transport", "category": "database", "risk": "high", "description": "Elasticsearch Transport"},
    {"port": 11211, "proto": "tcp", "name": "Memcached", "category": "database", "risk": "high", "description": "Memcached Cache Service"},
    {"port": 15672, "proto": "tcp", "name": "RabbitMQ Mgmt", "category": "messaging", "risk": "medium", "description": "RabbitMQ Management UI"},
    {"port": 27017, "proto": "tcp", "name": "MongoDB", "category": "database", "risk": "critical", "description": "MongoDB Database"},
    {"port": 27018, "proto": "tcp", "name": "MongoDB Secondary", "category": "database", "risk": "critical", "description": "MongoDB Secondary Node"},
]


async def seed_known_services(db: AsyncSession) -> int:
    """Seed known services if table is empty. Returns count of inserted records."""
    result = await db.execute(select(KnownService).limit(1))
    if result.scalar_one_or_none():
        return 0
    count = 0
    for svc in KNOWN_SERVICES:
        db.add(KnownService(**svc))
        count += 1
    await db.commit()
    return count
