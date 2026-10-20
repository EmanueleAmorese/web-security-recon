#!/usr/bin/env python3
"""
recon.py — Analizzatore della postura di sicurezza di un sito web.

Interroga un URL e valuta la sua "superficie d'attacco" osservando ciò che il
server dichiara apertamente: intestazioni (header) di sicurezza presenti o
mancanti, flag dei cookie, informazioni rivelate dal server. Assegna un voto e
spiega ogni problema. È uno strumento di RICOGNIZIONE: legge soltanto quello che
il sito risponde già a un normale browser, non esegue alcun attacco.

  python3 recon.py --demo
  python3 recon.py https://example.com --json report.json

Solo libreria standard, nessuna dipendenza.

⚠️ USO LECITO: analizza solo siti tuoi o per cui hai un permesso esplicito.
La ricognizione non autorizzata di sistemi altrui può essere illegale.
"""
from __future__ import annotations

import argparse
import json
import sys
import urllib.request
from dataclasses import dataclass, field

# Header di sicurezza che un sito ben configurato dovrebbe inviare.
# Per ciascuno: a cosa serve, cioè quale attacco aiuta a prevenire.
SECURITY_HEADERS = {
    "strict-transport-security": "Obbliga il browser a usare sempre HTTPS (previene il downgrade a HTTP).",
    "content-security-policy":   "Limita da dove si possono caricare script: principale difesa contro l'XSS.",
    "x-frame-options":           "Impedisce di incorniciare il sito in un iframe (previene il clickjacking).",
    "x-content-type-options":    "Impedisce al browser di 'indovinare' il tipo di file (MIME sniffing).",
    "referrer-policy":           "Controlla quante informazioni sull'URL vengono passate ad altri siti.",
    "permissions-policy":        "Disattiva funzioni del browser non necessarie (fotocamera, geolocalizzazione…).",
}

# Header che RIVELANO informazioni utili a un attaccante: meglio non esporli.
DISCLOSURE_HEADERS = {
    "server": "Rivela il software del server (e a volte la versione): aiuta a cercare exploit noti.",
    "x-powered-by": "Rivela la tecnologia usata (es. PHP/versione): informazione di troppo.",
    "x-aspnet-version": "Rivela la versione di ASP.NET: informazione di troppo.",
}


# Finding: UN singolo esito dell'analisi (un controllo). 'level' ne dice la
# gravità: "ok" = va bene, "warn" = da migliorare, "bad" = problema grave.
@dataclass
class Finding:
    level: str        # "ok" | "warn" | "bad"
    title: str
    detail: str


# Report: la "pagella" completa di un sito — URL, stato HTTP, se usa HTTPS e la
# lista di tutti i Finding. Da questa lista ricava punteggio (score) e voto (grade).
@dataclass
class Report:
    url: str
    status: int
    https: bool
    findings: list[Finding] = field(default_factory=list)

    # add: aggiunge un nuovo Finding (un problema o una conferma) al report.
    def add(self, level: str, title: str, detail: str) -> None:
        self.findings.append(Finding(level, title, detail))

    @property
    def score(self) -> int:
        """Punteggio 0–100: parte da 100 e toglie punti per ogni problema."""
        penalty = sum({"bad": 20, "warn": 8}.get(f.level, 0) for f in self.findings)
        return max(0, 100 - penalty)

    # grade: traduce il punteggio numerico in un voto da A (ottimo) a F (pessimo).
    @property
    def grade(self) -> str:
        s = self.score
        return "A" if s >= 90 else "B" if s >= 75 else "C" if s >= 60 else "D" if s >= 40 else "F"


# ---------------------------------------------------------------------------
# analisi: guarda gli header e costruisce l'elenco dei problemi (findings)
# ---------------------------------------------------------------------------
def analyze(url: str, status: int, headers: dict[str, str]) -> Report:
    # normalizza i nomi header a minuscolo (gli header sono case-insensitive)
    h = {k.lower(): v for k, v in headers.items()}
    rep = Report(url=url, status=status, https=url.lower().startswith("https://"))

    # 1. HTTPS
    if rep.https:
        rep.add("ok", "HTTPS", "La connessione usa HTTPS.")
    else:
        rep.add("bad", "HTTP in chiaro", "Il sito non usa HTTPS: i dati viaggiano leggibili.")

    # 2. Header di sicurezza presenti / mancanti
    for name, why in SECURITY_HEADERS.items():
        if name in h:
            rep.add("ok", f"Header presente: {name}", why)
        else:
            rep.add("warn", f"Header mancante: {name}", why)

    # 3. Informazioni rivelate dal server
    for name, why in DISCLOSURE_HEADERS.items():
        if name in h:
            rep.add("bad", f"Informazione esposta: {name} = {h[name]}", why)

    # 4. Flag dei cookie (Secure / HttpOnly / SameSite)
    cookie = h.get("set-cookie")
    if cookie:
        low = cookie.lower()
        if "secure" not in low:
            rep.add("warn", "Cookie senza 'Secure'", "Il cookie può viaggiare anche su HTTP non cifrato.")
        if "httponly" not in low:
            rep.add("warn", "Cookie senza 'HttpOnly'", "Il cookie è leggibile da JavaScript: rischio furto via XSS.")
        if "samesite" not in low:
            rep.add("warn", "Cookie senza 'SameSite'", "Manca la difesa contro gli attacchi CSRF.")

    return rep


# ---------------------------------------------------------------------------
# trasporto reale: fa una richiesta HTTP e restituisce stato + header
# ---------------------------------------------------------------------------
def http_fetch(url: str) -> tuple[int, dict[str, str]]:
    req = urllib.request.Request(url, headers={"User-Agent": "web-security-recon/1.0"})
    with urllib.request.urlopen(req, timeout=10) as resp:
        return resp.status, dict(resp.headers.items())


# trasporto finto per la demo: header tipici di un sito poco protetto (nessuna rete)
def demo_headers() -> tuple[str, int, dict[str, str]]:
    url = "http://sito-di-esempio.test"
    headers = {
        "Server": "Apache/2.4.29 (Ubuntu)",
        "X-Powered-By": "PHP/7.2.24",
        "Content-Type": "text/html; charset=UTF-8",
        "Set-Cookie": "session=abc123; Path=/",
        # niente header di sicurezza: così la demo mostra tanti 'mancanti'
    }
    return url, 200, headers


# ---------------------------------------------------------------------------
# stampa del report a schermo
# ---------------------------------------------------------------------------
MARK = {"ok": "[+]", "warn": "[!]", "bad": "[-]"}

# print_report: stampa a schermo la pagella (voto e punteggio) e poi l'elenco dei
# controlli, ciascuno col suo segno: [+] ok, [!] da migliorare, [-] grave.
def print_report(rep: Report) -> None:
    print(f"\n  Recon sicurezza web — {rep.url}")
    print(f"  Stato HTTP: {rep.status}   Voto: {rep.grade} ({rep.score}/100)\n")
    for f in rep.findings:
        print(f"  {MARK.get(f.level,'[ ]')} {f.title}")
        print(f"      {f.detail}")
    bad = sum(f.level == "bad" for f in rep.findings)
    warn = sum(f.level == "warn" for f in rep.findings)
    print(f"\n  Problemi gravi: {bad} · da migliorare: {warn}\n")


# main: punto di partenza del programma. Legge le opzioni dalla riga di comando,
# sceglie la modalità (demo o sito reale), lancia l'analisi, stampa il report e,
# se richiesto, lo salva in JSON. Esce con 1 se trova almeno un problema grave.
def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(description="Analizza la postura di sicurezza di un sito web (recon, sola lettura).")
    p.add_argument("url", nargs="?", help="URL da analizzare, es. https://example.com")
    p.add_argument("--demo", action="store_true", help="usa dati finti, senza rete")
    p.add_argument("--json", metavar="FILE", help="salva il report in JSON")
    args = p.parse_args(argv)

    if args.demo:
        url, status, headers = demo_headers()
    elif args.url:
        url = args.url if "://" in args.url else "https://" + args.url
        try:
            status, headers = http_fetch(url)
        except Exception as e:
            print(f"Errore nel contattare {url}: {e}", file=sys.stderr)
            return 2
    else:
        p.error("indica un URL oppure usa --demo")

    rep = analyze(url, status, headers)
    print_report(rep)

    if args.json:
        data = {
            "url": rep.url, "status": rep.status, "grade": rep.grade, "score": rep.score,
            "findings": [vars(f) for f in rep.findings],
        }
        with open(args.json, "w", encoding="utf-8") as fh:
            json.dump(data, fh, indent=2, ensure_ascii=False)
        print(f"  Report JSON salvato in: {args.json}\n")

    # exit 1 se c'e' almeno un problema grave: utile in una pipeline
    return 1 if any(f.level == "bad" for f in rep.findings) else 0


if __name__ == "__main__":
    raise SystemExit(main())
