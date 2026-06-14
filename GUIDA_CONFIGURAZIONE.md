# Guida alla Configurazione: Distributed BTC Key Search

Questa guida contiene tutte le istruzioni necessarie per configurare il sistema di scansione distribuito, inclusa l'installazione dei requisiti, la configurazione di rete sicura tramite **Tailscale VPN** e i comandi per avviare il Server Coordinator e i vari PC Worker.

---

## 1. Architettura di Rete e Flusso di Lavoro

* **PC SERVER (Centrale - Casa)**: Esegue Bitcoin Core, l'indicizzatore Fulcrum e lo script `server_coordinator.py` (sulla porta `8000`).
* **PC WORKER (Client - Ufficio/Portatili)**: Eseguono solo lo script `worker_client.py`. Calcolano le chiavi sulla propria CPU e interrogano Fulcrum sul server (sulla porta `50001`) in tempo reale.

---

## 2. Configurazione di Tailscale VPN (LAN Virtuale Sicura)

Per consentire ai PC Worker di connettersi al Server di casa da qualsiasi luogo (es. dall'ufficio o in mobilità) senza aprire porte sul router di casa (port forwarding), la soluzione ideale è usare **Tailscale**.

### A. Configurazione sul PC SERVER (Casa)
1. Vai su [https://tailscale.com/](https://tailscale.com/) e registrati gratuitamente (puoi accedere con Google, GitHub o Microsoft).
2. Scarica e installa il client Tailscale per Windows sul PC Server.
3. Al termine dell'installazione, clicca sull'icona di Tailscale nella barra delle applicazioni in basso a destra e seleziona **"Log in..."**.
4. Si aprirà una pagina web: effettua l'accesso con l'account registrato al punto 1.
5. Una volta effettuato l'accesso, Tailscale assegnerà un indirizzo IP VPN univoco al tuo PC Server (es. `100.80.90.120`). **Segna questo IP**, ti servirà per i client.

### B. Configurazione su ciascun PC WORKER (Ufficio/Portatili)
1. Scarica e installa il client Tailscale per Windows/Linux/macOS sul PC Worker.
2. Avvia l'applicazione e seleziona **"Log in..."**.
3. Accedi utilizzando **lo stesso identico account** usato per il PC Server.
4. Una volta effettuato l'accesso, il Worker farà parte della stessa rete privata virtuale del Server.
5. Per verificare che la connessione funzioni, apri il terminale del Worker e prova a fare un ping verso l'IP del Server:
   ```bash
   ping <IP_TAILSCALE_DEL_SERVER>
   ```
   *(Es. `ping 100.80.90.120`)*

---

## 3. Configurazione del PC SERVER

### A. File di Configurazione di Bitcoin Core (`bitcoin.conf`)
Il database di Bitcoin Core deve essere indicizzato e pronto a ricevere chiamate da Fulcrum. Verifica che contenga:
```ini
server=1
rpcallowip=127.0.0.1
rpcport=8332
txindex=1
prune=0
dbcache=12288
```

### B. File di Configurazione di Fulcrum (`fulcrum.conf`)
Fulcrum deve accettare connessioni TCP non solo da localhost, ma da tutta la rete privata (incluso l'IP di Tailscale). Imposta la voce `tcp` su `0.0.0.0`:
```ini
datadir = E:/FulcrumDB
bitcoind = 127.0.0.1:8332
rpccookie = D:/Block/.cookie

# Consenti connessioni esterne sulla porta 50001
tcp = 0.0.0.0:50001
admin = 127.0.0.1:8000
stats = 127.0.0.1:8080

peering = false
announce = false
db_mem = 12288
```

### C. Avvio dei Servizi sul Server
1. Assicurati che Bitcoin Core e Fulcrum siano avviati e sincronizzati.
2. Avvia il coordinatore HTTP aprendo il file `Avvia_Server.cmd` o tramite terminale nella cartella del progetto:
   ```powershell
   python server_coordinator.py
   ```
   *Il coordinatore si metterà in ascolto sulla porta `8000` ed inizierà a gestire i checkpoint locali.*

---

## 4. Configurazione del PC WORKER (Client)

I PC Worker non hanno bisogno della blockchain né di Fulcrum, rendendo la configurazione rapidissima.

### A. Requisiti software
1. Installa **Python 3** (scaricabile da [python.org](https://www.python.org/downloads/)). Durante l'installazione, assicurati di spuntare la voce **"Add Python to PATH"**.
2. Installa le dipendenze crittografiche necessarie aprendo la PowerShell/Prompt dei comandi del Worker ed eseguendo:
   ```powershell
   pip install cryptography base58
   ```

### B. Trasferimento del file client
Copia il file `worker_client.py` dal tuo computer principale al PC Worker (puoi inviarlo via email, chiavetta USB o tramite Dropbox).

### C. Test della crittografia locale sul Worker
Per essere sicuro che Python e le librerie crittografiche funzionino correttamente sul nuovo computer, esegui il test di derivazione:
```powershell
python worker_client.py --test-derivation
```
Se vedi il messaggio `Test superato con successo!`, la configurazione locale è corretta.

### D. Avvio della Scansione Distribuita
Per avviare la scansione ed iniziare a collaborare, esegui il comando inserendo l'IP Tailscale (o l'IP LAN locale se i PC si trovano nella stessa stanza) del PC Server:
```powershell
python worker_client.py --server <IP_TAILSCALE_DEL_SERVER> --port 8000
```
*(Es. `python worker_client.py --server 100.80.90.120 --port 8000`)*

*Il Worker richiederà un blocco di chiavi al server, deriverà gli indirizzi sulla propria CPU e interrogherà Fulcrum sull'IP specificato alla porta `50001`.*

---

## 5. Risoluzione dei Problemi (Troubleshooting)

* **Errore "Connessione rifiutata" o timeout sul Worker**:
  * Controlla che Tailscale sia attivo e connesso su entrambi i computer.
  * Verifica che il firewall di Windows sul PC Server consenta le connessioni in entrata per le porte **`8000`** e **`50001`**. Puoi aggiungere una regola sul firewall di Windows per sbloccarle o disattivarlo temporaneamente sulla rete privata/Tailscale per testare.
  * Verifica che in `fulcrum.conf` sia impostato `tcp = 0.0.0.0:50001` (e NON `127.0.0.1:50001`).
* **Calcolo lento della CPU**:
  * Lo script `worker_client.py` utilizza le funzioni crittografiche native di `cryptography` che fanno affidamento a OpenSSL compilato in C, garantendo ottime prestazioni. Chiudi eventuali processi pesanti in background sul Worker per dedicare la CPU interamente alla scansione.
