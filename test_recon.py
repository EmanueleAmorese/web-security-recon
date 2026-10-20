"""
test_recon.py — Test automatici per recon.py.

Un "test" è una piccola funzione che controlla da sola che il programma si
comporti come deve: prepara un caso finto, chiama il codice e verifica il
risultato con `assert`. Se un assert è falso, il test fallisce e lo vedi subito.
Avere i test su un progetto dice a chi lo guarda che il codice è affidabile.

Esegui:  python3 test_recon.py     (oppure: python3 -m pytest)
"""
import recon as r


# Un sito messo male (niente header di sicurezza, info del server esposte)
# deve prendere un voto basso (D o F) e avere almeno un problema grave.
def test_sito_insicuro_prende_voto_basso():
    headers = {"Server": "Apache/2.4.29", "X-Powered-By": "PHP/7.2",
               "Set-Cookie": "id=1; Path=/"}
    rep = r.analyze("http://x.test", 200, headers)
    assert rep.grade in ("D", "F")           # tanti problemi -> voto basso
    assert any(f.level == "bad" for f in rep.findings)   # HTTP + info esposte


# Un sito con tutti gli header di sicurezza e i cookie protetti
# deve prendere il voto massimo (A) e nessun problema grave.
def test_sito_sicuro_prende_voto_alto():
    headers = {
        "Strict-Transport-Security": "max-age=63072000",
        "Content-Security-Policy": "default-src 'self'",
        "X-Frame-Options": "DENY",
        "X-Content-Type-Options": "nosniff",
        "Referrer-Policy": "no-referrer",
        "Permissions-Policy": "geolocation=()",
        "Set-Cookie": "id=1; Secure; HttpOnly; SameSite=Strict",
    }
    rep = r.analyze("https://x.test", 200, headers)
    assert rep.grade == "A"
    assert all(f.level != "bad" for f in rep.findings)


# Un sito servito in HTTP (senza cifratura) deve essere segnalato come grave.
def test_http_segnalato_come_grave():
    rep = r.analyze("http://x.test", 200, {})
    assert any(f.level == "bad" and "HTTP" in f.title for f in rep.findings)


# Un cookie senza i flag di protezione deve far scattare le tre segnalazioni
# giuste: manca Secure, manca HttpOnly, manca SameSite.
def test_cookie_senza_flag_segnalato():
    rep = r.analyze("https://x.test", 200, {"Set-Cookie": "id=1"})
    titoli = " ".join(f.title for f in rep.findings)
    assert "HttpOnly" in titoli and "Secure" in titoli and "SameSite" in titoli


# Gli header HTTP sono "case-insensitive": vanno riconosciuti anche se scritti
# tutti in maiuscolo. Qui controlliamo che il programma non si faccia ingannare.
def test_header_case_insensitive():
    rep = r.analyze("https://x.test", 200, {"STRICT-TRANSPORT-SECURITY": "max-age=1"})
    assert any(f.level == "ok" and "strict-transport-security" in f.title for f in rep.findings)


# Questo blocco permette di lanciare i test anche senza pytest:
# esegue una per una tutte le funzioni che iniziano per "test_".
if __name__ == "__main__":
    for name, fn in sorted(globals().items()):
        if name.startswith("test_") and callable(fn):
            fn(); print(f"ok  {name}")
    print("Tutti i test passati.")
