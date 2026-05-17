"""
modules/port_scanner.py — Async TCP port scanner with banner grabbing
Author: 0xMasruful
"""

from __future__ import annotations

import asyncio
import ssl
import socket
from typing import Optional

from utils.output import print_module_header, print_info, print_warning, print_success

# Top ports with common service names
TOP_PORTS = {
    21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 53: "DNS",
    80: "HTTP", 110: "POP3", 111: "RPC", 135: "MSRPC", 139: "NetBIOS",
    143: "IMAP", 161: "SNMP", 389: "LDAP", 443: "HTTPS", 445: "SMB",
    512: "rexec", 513: "rlogin", 514: "syslog", 587: "SMTP/TLS",
    636: "LDAPS", 993: "IMAPS", 995: "POP3S",
    1080: "SOCKS", 1433: "MSSQL", 1521: "Oracle", 1723: "PPTP",
    2049: "NFS", 2181: "Zookeeper", 3000: "Node.js/Rails",
    3306: "MySQL", 3389: "RDP", 4444: "Metasploit",
    5000: "Flask/UPnP", 5432: "PostgreSQL", 5900: "VNC",
    6379: "Redis", 6443: "Kubernetes API", 7001: "WebLogic",
    8000: "HTTP-Alt", 8080: "HTTP-Proxy", 8081: "HTTP-Alt2",
    8443: "HTTPS-Alt", 8888: "HTTP-Alt3", 9000: "PHP-FPM",
    9090: "Prometheus", 9200: "Elasticsearch", 9300: "Elasticsearch-Internal",
    27017: "MongoDB", 50000: "SAP",
}


async def _tcp_connect(host: str, port: int, timeout: float = 2.0) -> bool:
    """Try to establish a TCP connection."""
    try:
        _, writer = await asyncio.wait_for(
            asyncio.open_connection(host, port),
            timeout=timeout,
        )
        writer.close()
        try:
            await writer.wait_closed()
        except Exception:
            pass
        return True
    except (ConnectionRefusedError, asyncio.TimeoutError, OSError):
        return False


async def _grab_banner(host: str, port: int, timeout: float = 3.0) -> str:
    """Attempt to grab service banner."""
    try:
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(host, port),
            timeout=timeout,
        )
        # HTTP-like ports: send HEAD request
        if port in (80, 8080, 8000, 8081, 8888):
            writer.write(b"HEAD / HTTP/1.0\r\nHost: " + host.encode() + b"\r\n\r\n")
        elif port in (443, 8443):
            writer.close()
            return await _grab_https_banner(host, port, timeout)
        else:
            writer.write(b"\r\n")

        await writer.drain()
        banner = await asyncio.wait_for(reader.read(256), timeout=timeout)
        writer.close()
        try:
            await writer.wait_closed()
        except Exception:
            pass
        return banner.decode("utf-8", errors="replace").strip()[:120]
    except Exception:
        return ""


async def _grab_https_banner(host: str, port: int, timeout: float = 3.0) -> str:
    """Grab banner over TLS."""
    try:
        ctx_ssl = ssl.create_default_context()
        ctx_ssl.check_hostname = False
        ctx_ssl.verify_mode = ssl.CERT_NONE
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(host, port, ssl=ctx_ssl),
            timeout=timeout,
        )
        writer.write(b"HEAD / HTTP/1.0\r\nHost: " + host.encode() + b"\r\n\r\n")
        await writer.drain()
        banner = await asyncio.wait_for(reader.read(256), timeout=timeout)
        writer.close()
        return banner.decode("utf-8", errors="replace").strip()[:120]
    except Exception:
        return ""


async def _check_tls(host: str, port: int, timeout: float = 3.0) -> bool:
    """Check if port speaks TLS."""
    if port in (443, 8443, 636, 993, 995):
        return True
    try:
        ctx_ssl = ssl.create_default_context()
        ctx_ssl.check_hostname = False
        ctx_ssl.verify_mode = ssl.CERT_NONE
        _, writer = await asyncio.wait_for(
            asyncio.open_connection(host, port, ssl=ctx_ssl),
            timeout=timeout,
        )
        writer.close()
        return True
    except Exception:
        return False


async def run_port_scanner(ctx) -> None:
    """Async TCP port scanner — scans top ports for open services."""
    ports_to_scan = list(TOP_PORTS.keys())
    if ctx.full_ports:
        ports_to_scan = list(range(1, 65536))

    print_module_header("Port Scanner", f"{len(ports_to_scan)} ports → {ctx.host}")

    open_ports: dict[int, dict] = {}
    sem = asyncio.Semaphore(min(ctx.threads, 200))

    async def scan_port(port: int):
        async with sem:
            is_open = await _tcp_connect(ctx.host, port, timeout=2.0)
            if is_open:
                service = TOP_PORTS.get(port, "unknown")
                banner = await _grab_banner(ctx.host, port)
                tls = await _check_tls(ctx.host, port)
                open_ports[port] = {
                    "port": port,
                    "state": "open",
                    "service": service,
                    "banner": banner,
                    "tls": tls,
                }
                tls_mark = " 🔒" if tls else ""
                banner_preview = banner[:60] if banner else ""
                print_info(f"  OPEN  {port:5}/tcp  {service:15}{tls_mark}  {banner_preview}")

    tasks = [asyncio.create_task(scan_port(p)) for p in ports_to_scan]
    await asyncio.gather(*tasks, return_exceptions=True)

    ctx.ports = open_ports
    ctx.module_status["ports"] = "ok"
    print_success(f"Port scan complete — {len(open_ports)} open ports")
