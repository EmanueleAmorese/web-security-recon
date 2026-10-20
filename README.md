# Web Security Recon

Strumento a riga di comando che analizza la **postura di sicurezza** di un sito
web: interroga un URL e valuta la sua superficie d'attacco osservando ciò che il
server dichiara apertamente — intestazioni (header) di sicurezza presenti o
mancanti, flag dei cookie, informazioni rivelate dal server. Assegna un voto da
A a F e spiega ogni problema.

È un progetto pensato come esercizio di **ricognizione (recon)**, la prima fase
del lavoro offensivo: studiare un bersaglio prima di valutarne le debolezze.

> **Sola lettura.** Lo strumento fa una normale richiesta HTTP e legge la
> risposta, esattamente come un browser. **Non esegue alcun attacco**: non prova
> password, non invia payload, non sfrutta vulnerabilità.

## ⚠️ Uso lecito

Analizza **solo siti tuoi o per cui hai un permesso esplicito**. Anche la sola
ricognizione di sistemi altrui, senza autorizzazione, può costituire un illecito.
L'autorizzazione è la prima regola del lavoro offensivo: questo strumento la
rispetta per scelta.

## Cosa controlla

| Area | Esempi |
|---|---|
| **HTTPS** | la connessione è cifrata? |
| **Header di sicurezza** | HSTS, Content-Security-Policy, X-Frame-Options, X-Content-Type-Options, Referrer-Policy, Permissions-Policy |
| **Cookie** | flag `Secure`, `HttpOnly`, `SameSite` |
| **Information disclosure** | il server rivela software e versioni (`Server`, `X-Powered-By`)? |

Ogni controllo è spiegato con **l'attacco che aiuta a prevenire** (XSS,
clickjacking, CSRF, downgrade a HTTP…), così lo strumento insegna mentre analizza.

## Come si usa

```bash
# Demo senza rete: mostra il referto di un sito poco protetto
python3 recon.py --demo

# Analisi di un sito reale (tuo o autorizzato)
python3 recon.py https://tuo-sito.example --json report.json
```

Esempio di output:

```
  Recon sicurezza web — https://tuo-sito.example
  Stato HTTP: 200   Voto: C (64/100)

  [+] HTTPS
  [!] Header mancante: content-security-policy
      Limita da dove si possono caricare script: principale difesa contro l'XSS.
  [-] Informazione esposta: server = Apache/2.4.29
```

Legenda: `[+]` ok · `[!]` da migliorare · `[-]` problema grave.
**Exit code:** `0` nessun problema grave, `1` almeno uno (utile in una pipeline).

## Come è fatto

- **Python 3, solo libreria standard** (nessuna dipendenza).
- Logica separata dal trasporto di rete: la funzione `analyze` lavora su un
  dizionario di header, quindi i test girano **senza rete** passandole header
  finti. Il trasporto reale (`http_fetch`) e la demo sono intercambiabili.

## Test

```bash
python3 test_recon.py      # oppure: python3 -m pytest
```

## Possibili sviluppi

- Controllo della versione del protocollo TLS e della scadenza del certificato.
- Segnalazione di pagine di login servite in HTTP.
- Export in formato compatibile con altri strumenti di security testing.

---
*Progetto didattico. Usalo solo su sistemi di cui sei proprietario o per i quali
hai un'autorizzazione scritta.*
