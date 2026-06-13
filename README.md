# Distributed BTC Key Search

Verificatore di chiavi private Bitcoin distribuito ad alte prestazioni su rete locale (LAN) o remota (tramite VPN/Tailscale).

Questo progetto consente a molteplici PC (Workers) di unire le proprie forze di calcolo per scansionare chiavi private sequenziali, delegando le interrogazioni del database a un singolo PC centrale (Server) che ospita la blockchain di Bitcoin Core e l'indicizzatore Fulcrum.

---

## Architettura Distribuita

```text
  [Worker 1 (PC Lavoro)]          [Worker 2 (PC Casa 2)]
         |                                |
         |-- (1. Chiede blocco HTTP)      |
         |-- (2. Calcola chiavi CPU)      |
         |-- (3. Query TCP Fulcrum) ------+---> [Server Centrale (PC Casa 1)]
         |                                        - server_coordinator.py (Port 8000)
         v                                        - Fulcrum (Port 50001)
  [Worker 3 (LAN Portatile)]                      - Bitcoin Core (Port 8332)
```

1. **Server Coordinator (`server_coordinator.py`)**:
   Gestisce in modo centralizzato il checkpoint e la progressione complessiva. Distribuisce blocchi di lavoro (es. 100.000 chiavi) ai worker ed aspetta i loro report. Se riceve la segnalazione di un saldo positivo, arresta immediatamente tutti i worker.
2. **Worker Client (`worker_client.py`)**:
   Richiede un blocco al server, calcola gli indirizzi localmente sfruttando al 100% la propria CPU, ed interroga direttamente Fulcrum sul server in formato batch TCP. Se trova un saldo attivo, si arresta subito e invia la notifica al Server Coordinator.

---

## Configurazione del Server Centrale

Il server principale deve avere in esecuzione **Bitcoin Core** e **Fulcrum** ed essere configurato per ricevere connessioni dagli altri computer.

### 1. Configurazione di Bitcoin Core (`bitcoin.conf`)
Assicurati che il file `bitcoin.conf` (nella cartella dati di Core) contenga:
```ini
server=1
rpcallowip=127.0.0.1
rpcport=8332
txindex=1
prune=0
dbcache=12288
```

### 2. Configurazione di Fulcrum (`fulcrum.conf`)
Modifica `fulcrum.conf` per consentire connessioni non solo da localhost, ma da qualsiasi IP della rete (`0.0.0.0`):
```ini
datadir = E:/FulcrumDB
bitcoind = 127.0.0.1:8332
rpccookie = D:/Block/.cookie

tcp = 0.0.0.0:50001
admin = 127.0.0.1:8000
stats = 127.0.0.1:8080

peering = false
announce = false
db_mem = 12288
```

---

## Configurazione di Rete (LAN o Remoto)

Per consentire ai Worker di comunicare con il Server Coordinator (HTTP `8000`) e con Fulcrum (TCP `50001`):

### Caso A: Rete Locale (LAN)
I worker devono connettersi all'indirizzo IP locale del Server (es. `192.168.1.50`). Assicurati che il firewall del PC Server consenta le connessioni in entrata sulle porte `8000` (TCP) e `50001` (TCP).

### Caso B: Connessione Remota via Internet (es. PC del Lavoro)
La soluzione consigliata e più sicura in assoluto è installare **Tailscale** su tutti i PC:
1. Registrati gratuitamente su [tailscale.com](https://tailscale.com/).
2. Installa il client di Tailscale sul PC Server di casa e sui PC Worker (es. computer del lavoro).
3. Tutti i computer entreranno in una rete virtuale privata sicura ed crittografata.
4. I worker utilizzeranno l'indirizzo IP di Tailscale assegnato al PC Server (es. `100.x.y.z`) per connettersi sia all'HTTP coordinator (porta `8000`) sia a Fulcrum (porta `50001`) senza dover configurare il router o aprire porte pubbliche.

---

## Come Avviare il Sistema

### 1. Requisiti sui Worker
Tutti i PC Worker devono avere installato Python 3 e i pacchetti di derivazione crittografica:
```powershell
pip install cryptography base58
```

### 2. Avvio del Server Coordinator (Sul PC Server di casa)
Esegui sul server centrale nella cartella del progetto:
```powershell
python server_coordinator.py
```
*Questo avvierà il coordinatore in ascolto sulla porta `8000` e leggerà il progresso da `checkpoint.json`.*

### 3. Avvio dei Worker Client (Sui PC Worker)
Esegui su ciascun PC lavoratore indicando l'IP del server:
```powershell
python worker_client.py --server <IP_DEL_SERVER_CENTRALE> --port 8000
```
*Sostituisci `<IP_DEL_SERVER_CENTRALE>` con l'IP locale (es. `192.168.1.50`) o con l'IP di Tailscale (es. `100.x.y.z`). Lo script si collegherà automaticamente sia a Fulcrum (porta `50001`) che al coordinatore (porta `8000`) usando quell'IP.*

---

## Gestione dei Saldi e Arresto
* **Se un Worker trova un saldo attivo**: si ferma all'istante, notifica il server che provvede a salvare i dati (WIF inclusa) in `risultati.json` ed imposta lo stato di "STOP".
* **Gli altri Worker**: alla richiesta del blocco successivo (o al termine del loro blocco), riceveranno l'ordine di spegnimento dal server e si arresteranno automaticamente a loro volta.
* **Checkpoint**: il Server Coordinator aggiorna automaticamente `checkpoint.json` sul proprio disco locale ogni volta che un worker completa un blocco o se viene segnalato un saldo positivo.
