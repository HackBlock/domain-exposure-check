#!/usr/bin/env python3
"""
domain-exposure-check — HackBlock OSINT Scanner
Versión: 1.0.0  
"""

import argparse
import dns.resolver
import json
import re
import socket
import sys
import os
from dataclasses import dataclass, field
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor
import urllib.request
import urllib.error

# ──────────────────────────────────────────────────────────────
# UI & Estética (Colores y Formato)
# ──────────────────────────────────────────────────────────────

class UI:
    RESET  = "\033[0m"
    BOLD   = "\033[1m"
    RED    = "\033[91m"
    YELLOW = "\033[93m"
    GREEN  = "\033[92m"
    CYAN   = "\033[96m"
    GRAY   = "\033[90m"
    WHITE  = "\033[97m"
    
    @classmethod
    def disable(cls):
        cls.RESET = cls.BOLD = cls.RED = cls.YELLOW = cls.GREEN = cls.CYAN = cls.GRAY = cls.WHITE = ""

def bold(t): return f"{UI.BOLD}{t}{UI.RESET}"
def gray(t): return f"{UI.GRAY}{t}{UI.RESET}"
def cyan(t): return f"{UI.CYAN}{t}{UI.RESET}"

# ──────────────────────────────────────────────────────────────
# Estructuras de Datos
# ──────────────────────────────────────────────────────────────

@dataclass
class CheckResult:
    name: str
    status: str 
    detail: str
    score_impact: int
    recommendation: str = ""
    raw_data: list = field(default_factory=list) # Para mostrar los registros DNS exactos

@dataclass
class ScanReport:
    domain: str
    scan_date: str
    score: int
    risk_level: str
    checks: list = field(default_factory=list)
    exposed_emails: list = field(default_factory=list)
    typosquats_found: list = field(default_factory=list)
    summary: str = ""
    about: str = "Este informe ha sido generado por domain-exposure-check de HackBlock. Expertos en simulación de phishing y seguridad humana. https://hack-block.com"

# ──────────────────────────────────────────────────────────────
# Lógica de Escaneo DNS (Con detalle de registros)
# ──────────────────────────────────────────────────────────────

def check_spf(domain: str) -> CheckResult:
    try:
        answers = dns.resolver.resolve(domain, 'TXT')
        spf_records = [r.to_text().strip('"') for r in answers if 'v=spf1' in r.to_text()]
        
        if not spf_records:
            return CheckResult("SPF", "fail", "No se encontró registro SPF.", -20, "Configura SPF para evitar que suplanten tu dominio.", [])
        
        spf = spf_records[0]
        if len(spf_records) > 1:
            return CheckResult("SPF", "warn", f"Múltiples registros ({len(spf_records)}). Configuración inválida.", -10, "Fusiona tus registros SPF.", spf_records)
        
        status = "ok" if "-all" in spf else "warn"
        impact = 0 if "-all" in spf else -5
        detail = "Política estricta detectada." if "-all" in spf else "Modo softfail (~all) o permisivo."
        
        return CheckResult("SPF", status, detail, impact, "" if status == "ok" else "Cambia a -all para mayor protección.", spf_records)
    except Exception:
        return CheckResult("SPF", "fail", "Sin registros TXT/SPF.", -20, "El dominio es vulnerable a spoofing básico.", [])

def check_dmarc(domain: str) -> CheckResult:
    try:
        answers = dns.resolver.resolve(f"_dmarc.{domain}", 'TXT')
        dmarc_records = [r.to_text().strip('"') for r in answers if 'v=DMARC1' in r.to_text()]
        if not dmarc_records: raise Exception()
        
        dmarc = dmarc_records[0]
        policy = "none"
        if "p=reject" in dmarc: return CheckResult("DMARC", "ok", "Política de rechazo activa.", 0, "", dmarc_records)
        if "p=quarantine" in dmarc: return CheckResult("DMARC", "warn", "Política en cuarentena.", -10, "Eleva a p=reject.", dmarc_records)
        return CheckResult("DMARC", "fail", "Modo p=none (solo monitoreo).", -20, "Configura p=quarantine o reject.", dmarc_records)
    except Exception:
        return CheckResult("DMARC", "fail", "No se detectó registro DMARC.", -25, "Implementa DMARC para proteger tu reputación.", [])

def check_dkim(domain: str) -> CheckResult:
    # Selectores comunes para pre-sale rápida
    selectors = ["google", "default", "mail", "k1", "smtp", "s1"]
    found = []
    for s in selectors:
        try:
            target = f"{s}._domainkey.{domain}"
            dns.resolver.resolve(target, 'TXT')
            found.append(s)
        except: continue
    
    if found:
        return CheckResult("DKIM", "ok", f"Detectado con selector(es): {', '.join(found)}", 0, "", [f"Selector: {s}" for s in found])
    return CheckResult("DKIM", "warn", "No se encontró DKIM en selectores comunes.", -10, "Verifica la firma digital de tus correos.")

def check_mx(domain: str) -> CheckResult:
    try:
        answers = dns.resolver.resolve(domain, 'MX')
        mx_records = sorted([f"{r.preference} {r.exchange.to_text().rstrip('.')}" for r in answers])
        return CheckResult("Servidores MX", "info", f"{len(mx_records)} servidores configurados.", 0, "", mx_records)
    except:
        return CheckResult("Servidores MX", "fail", "No se encontraron servidores de correo.", 0)

# ──────────────────────────────────────────────────────────────
# Typosquatting Concurrente
# ──────────────────────────────────────────────────────────────

def resolve_dns(variant):
    try:
        socket.setdefaulttimeout(1.2)
        socket.gethostbyname(variant)
        return variant
    except: return None

def check_typosquatting(domain: str) -> tuple:
    name, tld = domain.rsplit('.', 1)
    variants = {f"{name}s.{tld}", f"login-{name}.{tld}", f"{name}-secure.{tld}", f"webmail-{name}.{tld}"}
    # Omissions
    for i in range(len(name)): variants.add(name[:i] + name[i+1:] + '.' + tld)

    with ThreadPoolExecutor(max_workers=25) as executor:
        found = [r for r in list(executor.map(resolve_dns, list(variants))) if r]

    impact = max(-20, -5 * len(found))
    return CheckResult("Typosquatting", "warn" if found else "ok", f"{len(found)} variantes activas encontradas.", impact), found

# ──────────────────────────────────────────────────────────────
# OSINT (Hunter.io)
# ──────────────────────────────────────────────────────────────

def check_hunter(domain, key):
    if not key: return CheckResult("Hunter.io", "skip", "API Key no detectada.", 0), []
    try:
        url = f"https://api.hunter.io/v2/domain-search?domain={domain}&api_key={key}&limit=10"
        req = urllib.request.Request(url, headers={'User-Agent': 'HackBlock-Scanner'})
        with urllib.request.urlopen(req, timeout=8) as r:
            data = json.loads(r.read().decode())
            total = data.get('data', {}).get('meta', {}).get('total', 0)
            emails = [e.get('value') for e in data.get('data', {}).get('emails', [])]
            return CheckResult("Emails Expuestos", "warn" if total > 0 else "ok", f"{total} correos encontrados.", -10 if total > 5 else 0), emails
    except: return CheckResult("Hunter.io", "skip", "Error de conexión API.", 0), []

# ──────────────────────────────────────────────────────────────
# Reporte Visual
# ──────────────────────────────────────────────────────────────

def print_banner():
    print(f"\n{UI.CYAN}{bold('╔══════════════════════════════════════════════════════════╗')}")
    print(f"║         {bold('domain-exposure-check')}  •  by {UI.CYAN}HackBlock{UI.CYAN}              ║")
    print(f"║         {UI.GRAY}Analizador de superficie de ataque OSINT{UI.CYAN}              ║")
    print(f"╚══════════════════════════════════════════════════════════╝{UI.RESET}\n")

def render_report(report: ScanReport):
    print_banner()
    print(f"  {bold('DOMINIO:')} {UI.CYAN}{report.domain}{UI.RESET}")
    print(f"  {bold('FECHA:')}   {UI.GRAY}{report.scan_date}{UI.RESET}\n")

    # Score
    color = UI.GREEN if report.score >= 80 else (UI.YELLOW if report.score >= 55 else UI.RED)
    bar = "█" * (report.score // 10) + "░" * (10 - report.score // 10)
    print(f"  {bold('PUNTUACIÓN DE SEGURIDAD')}")
    print(f"  {color}{bar}  {report.score}/100 — RIESGO {report.risk_level}{UI.RESET}\n")
    print(f"  {UI.GRAY}{'─' * 60}{UI.RESET}")

    for c in report.checks:
        icon = {"ok": UI.GREEN+"✓", "warn": UI.YELLOW+"⚠", "fail": UI.RED+"✗", "info": UI.CYAN+"i", "skip": UI.GRAY+"–"}.get(c.status, " ")
        print(f"  {icon}{UI.RESET} {bold(c.name):<18} {c.detail}")
        
        # Mostrar registros DNS si existen
        if c.raw_data:
            for line in c.raw_data:
                print(f"      {UI.GRAY}⮑  {UI.WHITE}{line}{UI.RESET}")
        
        if c.recommendation:
            print(f"      {UI.YELLOW}└─ Rec: {c.recommendation}{UI.RESET}")
        print()

    if report.typosquats_found:
        print(f"  {UI.GRAY}{'─' * 60}{UI.RESET}")
        print(f"  {UI.RED}{bold('⚠ DOMINIOS SOSPECHOSOS DETECTADOS (TYPOSQUATTING):')}{UI.RESET}")
        for t in report.typosquats_found:
            print(f"    • {t}")
        print()

    if report.exposed_emails:
        print(f"  {bold('CORREOS EXPUESTOS (MUESTRA):')}")
        for e in report.exposed_emails[:5]:
            print(f"    {UI.GRAY}• {e}{UI.RESET}")
        print()

    print(f"  {UI.GRAY}{'─' * 60}{UI.RESET}")
    print(f"  {UI.CYAN}{bold('HACKBLOCK CIBERSECURITY')}{UI.RESET}")
    print(f"  {UI.WHITE}{report.about}{UI.RESET}")
    print(f"  {UI.GRAY}Más info: https://hack-block.com    Repositorio oficial: https://github.com/HackBlock/domain-exposure-check{UI.RESET}\n")

# ──────────────────────────────────────────────────────────────
# Main
# ──────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('domain', help='Dominio a escanear')
    parser.add_argument('--json', action='store_true')
    parser.add_argument('--hunter-key', default=os.getenv('HUNTER_API_KEY', ''))
    
    args = parser.parse_args()
    
    # Limpiar dominio
    dom = args.domain.lower().replace("https://","").replace("http://","").replace("www.","").split('/')[0]

    # Ejecución
    results = []
    results.append(check_spf(dom))
    results.append(check_dmarc(dom))
    results.append(check_dkim(dom))
    results.append(check_mx(dom))
    
    typo_res, typos = check_typosquatting(dom)
    results.append(typo_res)
    
    hunter_res, emails = check_hunter(dom, args.hunter_key)
    results.append(hunter_res)

    # Score Final
    total_score = max(0, min(100, 100 + sum(c.score_impact for c in results)))
    level = "BAJO" if total_score >= 80 else ("MEDIO" if total_score >= 55 else "ALTO")
    if total_score < 30: level = "CRÍTICO"

    report = ScanReport(
        domain=dom,
        scan_date=datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        score=total_score,
        risk_level=level,
        checks=results,
        exposed_emails=emails,
        typosquats_found=typos
    )

    if args.json:
        print(json.dumps(report.__dict__, default=lambda x: x.__dict__, indent=2, ensure_ascii=False))
    else:
        render_report(report)

if __name__ == "__main__":
    main()
