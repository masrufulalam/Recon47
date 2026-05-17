"""
modules/dns_recon.py — DNS reconnaissance module
Author: 0xMasruful
"""

from __future__ import annotations

import asyncio
import socket
from typing import Any

from utils.output import console, print_module_header, print_info, print_warning, print_success


async def run_dns_recon(ctx) -> None:
    """Perform comprehensive DNS reconnaissance on the target."""
    print_module_header("DNS Recon", f"target → {ctx.host}")

    results: dict[str, Any] = {}

    # --- A / AAAA Records ---
    try:
        import dns.resolver
        import dns.reversename
        import dns.zone
        import dns.query
        import dns.exception

        resolver = dns.resolver.Resolver()
        resolver.timeout = 5
        resolver.lifetime = 10

        for rtype in ["A", "AAAA", "MX", "NS", "TXT", "SOA", "CNAME"]:
            try:
                answers = resolver.resolve(ctx.host, rtype)
                records = [str(r) for r in answers]
                results[rtype] = records
                print_info(f"{rtype:6} → {', '.join(records[:3])}")
            except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN, dns.exception.DNSException):
                results[rtype] = []
            except Exception as e:
                results[rtype] = []
                if ctx.verbose:
                    print_warning(f"DNS {rtype} query failed: {e}")

        # --- Zone Transfer Attempt (AXFR) ---
        ns_records = results.get("NS", [])
        axfr_results = []
        for ns in ns_records[:3]:
            try:
                ns_host = str(ns).rstrip(".")
                zone = dns.zone.from_xfr(dns.query.xfr(ns_host, ctx.host, timeout=5))
                axfr_results = [str(n) for n in zone.nodes.keys()]
                if axfr_results:
                    print_warning(f"ZONE TRANSFER SUCCESS on {ns_host}! Found {len(axfr_results)} records")
                    break
            except Exception:
                pass
        results["axfr"] = axfr_results

        # --- SPF / DMARC / DKIM from TXT ---
        txt_records = results.get("TXT", [])
        spf = [r for r in txt_records if "v=spf1" in r.lower()]
        dmarc_records = []
        dkim_records = []
        try:
            dmarc_ans = resolver.resolve(f"_dmarc.{ctx.host}", "TXT")
            dmarc_records = [str(r) for r in dmarc_ans]
        except Exception:
            pass
        try:
            dkim_ans = resolver.resolve(f"default._domainkey.{ctx.host}", "TXT")
            dkim_records = [str(r) for r in dkim_ans]
        except Exception:
            pass

        results["spf"] = spf
        results["dmarc"] = dmarc_records
        results["dkim"] = dkim_records

        if spf:
            print_info(f"SPF    → {spf[0][:80]}")
        if dmarc_records:
            print_info(f"DMARC  → {dmarc_records[0][:80]}")

        # --- Reverse DNS for A records ---
        ptr_map = {}
        for ip in results.get("A", [])[:5]:
            try:
                rev_name = dns.reversename.from_address(ip)
                ptr_ans = resolver.resolve(rev_name, "PTR")
                ptr_map[ip] = str(ptr_ans[0])
            except Exception:
                ptr_map[ip] = None
        results["ptr"] = ptr_map

    except ImportError:
        # Fallback to socket-based lookups
        print_warning("dnspython not available, falling back to socket lookups")
        try:
            ips = socket.gethostbyname_ex(ctx.host)
            results["A"] = ips[2]
            print_info(f"A → {', '.join(ips[2])}")
        except socket.gaierror as e:
            results["A"] = []
            print_warning(f"DNS lookup failed: {e}")

    # --- WHOIS ---
    whois_data = {}
    try:
        import whois as pywhois
        w = pywhois.whois(ctx.host)
        whois_data = {
            "registrar": str(w.registrar or ""),
            "creation_date": str(w.creation_date or ""),
            "expiration_date": str(w.expiration_date or ""),
            "name_servers": [str(n) for n in (w.name_servers or [])],
            "org": str(w.org or ""),
            "country": str(w.country or ""),
        }
        print_info(f"WHOIS  → Registrar: {whois_data.get('registrar', 'unknown')[:50]}")
    except Exception as e:
        whois_data = {"error": str(e)}
        if ctx.verbose:
            print_warning(f"WHOIS failed: {e}")

    ctx.dns = results
    ctx.whois = whois_data
    ctx.module_status["dns"] = "ok"
    print_success(f"DNS recon complete — {sum(len(v) if isinstance(v, list) else 1 for v in results.values() if v)} records collected")
