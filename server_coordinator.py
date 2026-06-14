import os
import sys
import json
import time
import datetime
import logging
import signal
from http.server import HTTPServer, BaseHTTPRequestHandler

# Setup Logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s [%(levelname)s] %(message)s',
    handlers=[
        logging.FileHandler("app.log", encoding="utf-8"),
        logging.StreamHandler(sys.stdout)
    ]
)

CHECKPOINT_FILE = "checkpoint.json"
RESULTS_FILE = "risultati.json"
PORT = 8000
BLOCK_SIZE = 100000  # Dimensione di default del blocco di chiavi da scansionare

# Stato Globale in memoria
server_state = {
    "next_private_key_number": 1,
    "checked_keys": 0,
    "stop_flag": False
}

# --- File Writing helpers (resilient to locks) ---
def safe_write_json(file_path, data):
    tmp_file = file_path + ".tmp"
    for attempt in range(15):
        try:
            with open(tmp_file, "w", encoding="utf-8") as f:
                json.dump(data, f, indent=2)
            os.replace(tmp_file, file_path)
            return
        except (PermissionError, OSError):
            if attempt == 14:
                raise
            time.sleep(0.1)

def save_checkpoint_on_disk():
    checkpoint = {
        "last_completed_private_key_number": str(server_state["next_private_key_number"] - 1),
        "next_private_key_number": str(server_state["next_private_key_number"]),
        "checked_keys": str(server_state["checked_keys"]),
        "updated_at": datetime.datetime.now().isoformat()
    }
    safe_write_json(CHECKPOINT_FILE, checkpoint)

def load_checkpoint_from_disk():
    if not os.path.exists(CHECKPOINT_FILE):
        checkpoint = {
            "last_completed_private_key_number": "0",
            "next_private_key_number": "1",
            "checked_keys": "0",
            "updated_at": None
        }
        safe_write_json(CHECKPOINT_FILE, checkpoint)
        return checkpoint
    
    try:
        with open(CHECKPOINT_FILE, "r", encoding="utf-8") as f:
            return json.load(f)
    except Exception as e:
        logging.error(f"Errore di lettura checkpoint: {e}. Ne creo uno nuovo.")
        checkpoint = {
            "last_completed_private_key_number": "0",
            "next_private_key_number": "1",
            "checked_keys": "0",
            "updated_at": None
        }
        safe_write_json(CHECKPOINT_FILE, checkpoint)
        return checkpoint

def save_positive_match(match_data):
    results = []
    if os.path.exists(RESULTS_FILE):
        try:
            with open(RESULTS_FILE, "r", encoding="utf-8") as f:
                results = json.load(f)
        except Exception as e:
            logging.error(f"Errore lettura risultati: {e}. Verrà sovrascritto.")
            
    results.append(match_data)
    safe_write_json(RESULTS_FILE, results)
    logging.info(f"!!! CHIAVE CON SALDO POSITIVO REGISTRATA !!! Salvata in {RESULTS_FILE}")

# --- HTTP Request Handler ---
class CoordinatorHandler(BaseHTTPRequestHandler):
    def log_message(self, format, *args):
        # Override per loggare tramite il modulo logging di Python ed escludere WIF
        logging.info("Richiesta HTTP: " + (format % args))

    def send_json(self, status_code, data):
        self.send_response(status_code)
        self.send_header('Content-Type', 'application/json')
        self.end_headers()
        self.wfile.write(json.dumps(data).encode('utf-8'))

    def do_GET(self):
        # 1. Endpoint: /request_work
        if self.path.startswith("/request_work"):
            if server_state["stop_flag"]:
                self.send_json(200, {"status": "stop", "message": "Ricerca interrotta: trovata chiave con saldo."})
                return
            
            # Assegna il blocco di lavoro
            start_key = server_state["next_private_key_number"]
            server_state["next_private_key_number"] += BLOCK_SIZE
            save_checkpoint_on_disk()
            
            logging.info(f"Assegnato blocco da #{start_key} a #{start_key + BLOCK_SIZE - 1}")
            
            self.send_json(200, {
                "status": "ok",
                "start": str(start_key),
                "count": str(BLOCK_SIZE)
            })
            return

        # 2. Endpoint: /status
        elif self.path == "/status" or self.path == "/":
            self.send_json(200, {
                "status": "scanning" if not server_state["stop_flag"] else "stopped",
                "next_private_key_number": str(server_state["next_private_key_number"]),
                "checked_keys": str(server_state["checked_keys"])
            })
            return

        # Endpoint non trovato
        self.send_json(404, {"error": "Endpoint non trovato"})

    def do_POST(self):
        # Legge il payload JSON
        content_length = int(self.headers.get('Content-Length', 0))
        post_data = self.rfile.read(content_length)
        
        try:
            payload = json.loads(post_data.decode('utf-8'))
        except Exception as e:
            self.send_json(400, {"error": f"JSON non valido: {e}"})
            return

        # 1. Endpoint: /report_completed
        if self.path == "/report_completed":
            count = int(payload.get("count", 0))
            server_state["checked_keys"] += count
            save_checkpoint_on_disk()
            logging.info(f"Worker {payload.get('worker_id', 'unknown')} ha completato un blocco di {count} chiavi. Totale verificate: {server_state['checked_keys']}")
            self.send_json(200, {"status": "acknowledged"})
            return

        # 2. Endpoint: /report_match
        elif self.path == "/report_match":
            has_active_balance = payload.get("has_active_balance", True)
            found_key = int(payload.get("private_key_number"))
            
            # Registra la vincita/storico nel file centrale risultati.json
            save_positive_match({
                "private_key_number": str(found_key),
                "wif": payload.get("wif"),
                "addresses": payload.get("addresses"),
                "results": payload.get("results"),
                "has_active_balance": has_active_balance,
                "found_by_worker": payload.get("worker_id", "unknown"),
                "found_at": datetime.datetime.now().isoformat()
            })
            
            if has_active_balance:
                server_state["stop_flag"] = True
                # Aggiorna il checkpoint esatto sulla chiave trovata
                server_state["next_private_key_number"] = found_key + 1
                save_checkpoint_on_disk()
                
                logging.info("======================================================================")
                logging.info(f"!!! RILEVATO SALDO ATTIVO DA WORKER {payload.get('worker_id')} !!!")
                logging.info(f"Chiave trovata: #{found_key}")
                logging.info("======================================================================")
            else:
                logging.info(f"Ricevuta chiave #{found_key} con storico transazioni (saldo zero) da worker {payload.get('worker_id')} - Registrata in risultati.json")
            
            self.send_json(200, {"status": "acknowledged"})
            return

        # Endpoint non trovato
        self.send_json(404, {"error": "Endpoint non trovato"})

def main():
    logging.info("Inizializzazione del Server Coordinator...")
    checkpoint = load_checkpoint_from_disk()
    
    server_state["next_private_key_number"] = int(checkpoint["next_private_key_number"])
    server_state["checked_keys"] = int(checkpoint["checked_keys"])
    
    logging.info(f"Partenza impostata a chiave #{server_state['next_private_key_number']} (verificate in passato: {server_state['checked_keys']})")
    
    server = HTTPServer(("0.0.0.0", PORT), CoordinatorHandler)
    logging.info(f"Server Coordinator avviato e in ascolto su HTTP port {PORT}...")
    
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        logging.info("Arresto del Server Coordinator...")
    finally:
        save_checkpoint_on_disk()
        server.server_close()
        logging.info("Server arrestato ordinatamente.")

if __name__ == "__main__":
    main()
