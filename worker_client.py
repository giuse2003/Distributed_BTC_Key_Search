import os
import sys
import json
import socket
import signal
import time
import logging
import datetime
import hashlib
import argparse
import urllib.request
import urllib.parse

import base58
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend

# Setup Logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s [%(levelname)s] %(message)s',
    handlers=[
        logging.FileHandler("app.log", encoding="utf-8"),
        logging.StreamHandler(sys.stdout)
    ]
)

BECH32_CHARSET = "qpzry9x8gf2tvdw0s3jn54khce6mua7l"
BATCH_SIZE = 100  # Numero di chiavi da verificare in una singola richiesta batch a Fulcrum
keep_running = True

def handle_sigint(signum, frame):
    global keep_running
    logging.info("Rilevato segnale di arresto (Ctrl+C). Termino il batch corrente ed esco...")
    keep_running = False

signal.signal(signal.SIGINT, handle_sigint)

# --- Bech32 Address Encoding for P2WPKH ---
def bech32_polymod(values):
    generators = [0x3b6a57b2, 0x26508e6d, 0x1ea119fa, 0x3d4233dd, 0x2a1462b3]
    checksum = 1
    for value in values:
        top = checksum >> 25
        checksum = (((checksum & 0x1ffffff) << 5) ^ value) & 0xffffffff
        for i in range(5):
            if (top >> i) & 1:
                checksum ^= generators[i]
    return checksum

def convert_bits(data, from_bits, to_bits, pad=True):
    acc = 0
    bits = 0
    ret = []
    maxv = (1 << to_bits) - 1
    max_acc = (1 << (from_bits + to_bits - 1)) - 1
    for value in data:
        if value < 0 or (value >> from_bits):
            return None
        acc = ((acc << from_bits) | value) & max_acc
        bits += from_bits
        while bits >= to_bits:
            bits -= to_bits
            ret.append((acc >> bits) & maxv)
    if pad:
        if bits:
            ret.append((acc << (to_bits - bits)) & maxv)
    elif bits >= from_bits or ((acc << (to_bits - bits)) & maxv):
        return None
    return ret

def segwit_address(program):
    converted = convert_bits(program, 8, 5)
    data = [0] + converted
    expanded = [3, 3, 0, 2, 3] + data + [0, 0, 0, 0, 0, 0]
    polymod = bech32_polymod(expanded) ^ 1
    checksum = []
    for i in range(6):
        checksum.append((polymod >> (5 * (5 - i))) & 31)
    return "bc1" + "".join(BECH32_CHARSET[v] for v in (data + checksum))

# --- Address and ScriptPubKey Derivation ---
def hash160(bytes_data):
    sha = hashlib.sha256(bytes_data).digest()
    h = hashlib.new('ripemd160')
    h.update(sha)
    return h.digest()

def derive_addresses_and_scripts(private_key_int):
    priv_bytes = private_key_int.to_bytes(32, byteorder='big')
    priv_key_obj = ec.derive_private_key(private_key_int, ec.SECP256K1(), default_backend())
    pub_key_obj = priv_key_obj.public_key()
    compressed_pubkey = pub_key_obj.public_bytes(
        encoding=serialization.Encoding.X962,
        format=serialization.PublicFormat.CompressedPoint
    )
    
    payload = b'\x80' + priv_bytes + b'\x01'
    wif = base58.b58encode_check(payload).decode('ascii')
    
    # Legacy P2PKH
    pubkey_hash = hash160(compressed_pubkey)
    legacy_addr = base58.b58encode_check(b'\x00' + pubkey_hash).decode('ascii')
    legacy_script = b'\x76\xa9\x14' + pubkey_hash + b'\x88\xac'
    
    # Nested SegWit P2SH-P2WPKH
    redeem_script = b'\x00\x14' + pubkey_hash
    redeem_hash = hash160(redeem_script)
    nested_addr = base58.b58encode_check(b'\x05' + redeem_hash).decode('ascii')
    nested_script = b'\xa9\x14' + redeem_hash + b'\x87'
    
    # Native SegWit P2WPKH
    native_addr = segwit_address(pubkey_hash)
    native_script = b'\x00\x14' + pubkey_hash
    
    scripthash_legacy = hashlib.sha256(legacy_script).digest()[::-1].hex()
    scripthash_nested = hashlib.sha256(nested_script).digest()[::-1].hex()
    scripthash_native = hashlib.sha256(native_script).digest()[::-1].hex()
    
    return {
        "wif": wif,
        "addresses": {
            "legacy": legacy_addr,
            "nested": nested_addr,
            "native": native_addr
        },
        "scripthashes": {
            "legacy": scripthash_legacy,
            "nested": scripthash_nested,
            "native": scripthash_native
        }
    }

# --- Persistent Fulcrum TCP Client ---
class FulcrumClient:
    def __init__(self, host, port=50001):
        self.host = host
        self.port = port
        self.sock = None
        self.sock_file = None
        
    def connect(self):
        self.close()
        self.sock = socket.create_connection((self.host, self.port), timeout=15)
        self.sock_file = self.sock.makefile('r', encoding='utf-8')
        
    def close(self):
        if self.sock_file:
            try: self.sock_file.close()
            except: pass
            self.sock_file = None
        if self.sock:
            try: self.sock.close()
            except: pass
            self.sock = None
            
    def send_batch(self, reqs):
        if not self.sock:
            self.connect()
        try:
            payload = json.dumps(reqs) + "\n"
            self.sock.sendall(payload.encode('utf-8'))
            line = self.sock_file.readline()
            if not line:
                raise Exception("Connessione chiusa da Fulcrum.")
            return json.loads(line)
        except Exception as e:
            self.close()
            raise e

    def query_history(self, scripthashes):
        reqs = []
        keys = ["legacy", "nested", "native"]
        for i, key in enumerate(keys):
            reqs.append({
                "jsonrpc": "2.0",
                "method": "blockchain.scripthash.get_history",
                "params": [scripthashes[key]],
                "id": i + 1000
            })
        try:
            resps = self.send_batch(reqs)
            resps.sort(key=lambda r: r.get("id", 0))
            return {
                "legacy": len(resps[0]["result"]) if isinstance(resps[0]["result"], list) else 0,
                "nested": len(resps[1]["result"]) if isinstance(resps[1]["result"], list) else 0,
                "native": len(resps[2]["result"]) if isinstance(resps[2]["result"], list) else 0
            }
        except Exception as e:
            logging.error(f"Errore query storico: {e}")
            return {"legacy": 0, "nested": 0, "native": 0}

# --- HTTP Communication Helper ---
def http_request(url, data=None):
    try:
        if data is not None:
            # POST Request
            req = urllib.request.Request(
                url,
                data=json.dumps(data).encode('utf-8'),
                headers={'Content-Type': 'application/json'},
                method='POST'
            )
        else:
            # GET Request
            req = urllib.request.Request(url, method='GET')
            
        with urllib.request.urlopen(req, timeout=10) as response:
            return json.loads(response.read().decode('utf-8'))
    except Exception as e:
        logging.error(f"Errore comunicazione HTTP con il server coordinator: {e}")
        return None

# --- Main Program Execution ---
def main():
    parser = argparse.ArgumentParser(description="Worker Client per scansione chiavi Bitcoin distribuita.")
    parser.add_argument("--server", default="127.0.0.1", help="Indirizzo IP del Server Coordinator.")
    parser.add_argument("--port", type=int, default=8000, help="Porta HTTP del Server Coordinator.")
    parser.add_argument("--fulcrum-host", help="Indirizzo IP di Fulcrum. Se omesso, usa lo stesso del server coordinator.")
    parser.add_argument("--fulcrum-port", type=int, default=50001, help="Porta TCP di Fulcrum.")
    parser.add_argument("--worker-id", help="ID unico del Worker. Se omesso, usa il nome del computer.")
    parser.add_argument("--test-derivation", action="store_true", help="Esegue un test di derivazione ed esce.")
    args = parser.parse_args()
    
    if args.test_derivation:
        logging.info("Avvio del test di derivazione...")
        derived = derive_addresses_and_scripts(1)
        assert derived['addresses']['legacy'] == "1BgGZ9tcN4rm9KBzDn7KprQz87SZ26SAMH", "Errore Legacy!"
        logging.info("Test superato con successo!")
        sys.exit(0)
        
    worker_id = args.worker_id if args.worker_id else socket.gethostname()
    fulcrum_host = args.fulcrum_host if args.fulcrum_host else args.server
    
    coordinator_url = f"http://{args.server}:{args.port}"
    logging.info(f"Avvio Worker '{worker_id}' | Server: {coordinator_url} | Fulcrum: {fulcrum_host}:{args.fulcrum_port}")
    
    client = FulcrumClient(fulcrum_host, args.fulcrum_port)
    
    while keep_running:
        # 1. Richiedi un blocco di lavoro al Server Coordinator
        logging.info("Richiesta di un nuovo blocco di lavoro...")
        url = f"{coordinator_url}/request_work?worker_id={urllib.parse.quote(worker_id)}"
        job = http_request(url)
        
        if job is None:
            logging.warning("Impossibile connettersi al Server Coordinator. Riprovo in 10 secondi...")
            time.sleep(10)
            continue
            
        if job.get("status") == "stop":
            logging.info(f"Ricevuto comando di arresto dal server: {job.get('message')}")
            break
            
        start_key = int(job["start"])
        count = int(job["count"])
        logging.info(f"Ricevuto blocco di lavoro: da #{start_key} a #{start_key + count - 1} ({count} chiavi)")
        
        # 2. Elabora il blocco di chiavi in batch
        block_completed = True
        found_funds = False
        fund_key_info = None
        
        offset = 0
        session_start_time = time.time()
        
        while offset < count and keep_running:
            batch_keys = []
            batch_requests = []
            
            for i in range(BATCH_SIZE):
                if offset + i >= count:
                    break
                current_key = start_key + offset + i
                derived = derive_addresses_and_scripts(current_key)
                batch_keys.append((current_key, derived))
                
                for addr_index, addr_type in enumerate(["legacy", "nested", "native"]):
                    sh = derived["scripthashes"][addr_type]
                    # Richiesta Saldo
                    batch_requests.append({
                        "jsonrpc": "2.0",
                        "method": "blockchain.scripthash.get_balance",
                        "params": [sh],
                        "id": i * 6 + addr_index * 2
                    })
                    # Richiesta Storico
                    batch_requests.append({
                        "jsonrpc": "2.0",
                        "method": "blockchain.scripthash.get_history",
                        "params": [sh],
                        "id": i * 6 + addr_index * 2 + 1
                    })
            
            # Interroga Fulcrum locale/remoto via TCP
            batch_responses = None
            while keep_running and batch_responses is None:
                try:
                    batch_responses = client.send_batch(batch_requests)
                except Exception as e:
                    logging.warning(f"Errore TCP Fulcrum durante scansione batch ({start_key + offset}-{start_key + offset + len(batch_keys) - 1}): {e}. Riprovo tra 10 secondi...")
                    client.close()
                    for _ in range(10):
                        if not keep_running:
                            break
                        time.sleep(1)
            
            if not keep_running:
                block_completed = False
                break
                
            batch_responses.sort(key=lambda r: r.get("id", 0))
            
            # Analizza i saldi del batch
            for idx, (current_key, derived) in enumerate(batch_keys):
                legacy_bal = batch_responses[idx * 6]["result"]
                legacy_hist = batch_responses[idx * 6 + 1]["result"]
                nested_bal = batch_responses[idx * 6 + 2]["result"]
                nested_hist = batch_responses[idx * 6 + 3]["result"]
                native_bal = batch_responses[idx * 6 + 4]["result"]
                native_hist = batch_responses[idx * 6 + 5]["result"]
                
                # Calcola saldi attivi
                total_sats = (legacy_bal.get("confirmed", 0) + legacy_bal.get("unconfirmed", 0) +
                              nested_bal.get("confirmed", 0) + nested_bal.get("unconfirmed", 0) +
                              native_bal.get("confirmed", 0) + native_bal.get("unconfirmed", 0))
                
                # Conta storico transazioni
                legacy_hist_count = len(legacy_hist) if isinstance(legacy_hist, list) else 0
                nested_hist_count = len(nested_hist) if isinstance(nested_hist, list) else 0
                native_hist_count = len(native_hist) if isinstance(native_hist, list) else 0
                total_hist_count = legacy_hist_count + nested_hist_count + native_hist_count
                
                has_active_balance = total_sats > 0
                has_past_history = total_hist_count > 0
                
                if has_active_balance or has_past_history:
                    results_data = {
                        "legacy": {
                            "confirmed": legacy_bal.get("confirmed", 0),
                            "unconfirmed": legacy_bal.get("unconfirmed", 0),
                            "history_count": legacy_hist_count
                        },
                        "nested": {
                            "confirmed": nested_bal.get("confirmed", 0),
                            "unconfirmed": nested_bal.get("unconfirmed", 0),
                            "history_count": nested_hist_count
                        },
                        "native": {
                            "confirmed": native_bal.get("confirmed", 0),
                            "unconfirmed": native_bal.get("unconfirmed", 0),
                            "history_count": native_hist_count
                        }
                    }
                    
                    report_payload = {
                        "worker_id": worker_id,
                        "private_key_number": str(current_key),
                        "wif": derived["wif"],
                        "addresses": derived["addresses"],
                        "results": results_data,
                        "has_active_balance": has_active_balance
                    }
                    
                    if has_active_balance:
                        # Trovato SALDO ATTIVO -> Ferma lo script client ed avvisa il Server
                        found_funds = True
                        fund_key_info = {
                            "number": current_key,
                            "wif": derived["wif"],
                            "addresses": derived["addresses"],
                            "payload": report_payload,
                            "total_sats": total_sats
                        }
                        break
                    else:
                        # Trovato SOLO STORICO PASSATO (saldo zero) -> Invia al Server ma NON fermare
                        logging.info(f"Trovata chiave #{current_key} con solo storico passato (saldo zero). Invio notifica non bloccante al server...")
                        http_request(f"{coordinator_url}/report_match", report_payload)
            
            if found_funds:
                break
                
            offset += len(batch_keys)
            
            # Stampa velocità ogni 5.000 chiavi
            if offset % 5000 == 0:
                elapsed = time.time() - session_start_time
                speed = offset / elapsed if elapsed > 0 else 0
                logging.info(f"Progresso blocco: {offset}/{count} | Velocità: {speed:.1f} chiavi/sec")
                
        # 3. Se troviamo una chiave con saldo positivo ATTUALE (bloccante)
        if found_funds:
            logging.info("======================================================================")
            logging.info(f"!!! RILEVATO SALDO ATTIVO SULLA CHIAVE #{fund_key_info['number']} !!!")
            logging.info(f"Saldo: {fund_key_info['total_sats']} sat")
            logging.info("Invio notifica bloccante di ritrovamento al server coordinator...")
            resp = http_request(f"{coordinator_url}/report_match", fund_key_info["payload"])
            client.close()
            logging.info("======================================================================")
            logging.info("Lo script Worker si è ARRESTATO correttamente.")
            logging.info("======================================================================")
            break
            
        # 4. Report di fine blocco (se completato con successo senza trovare nulla)
        if block_completed:
            logging.info(f"Blocco completato (saldo zero). Invio report di completamento al server...")
            http_request(f"{coordinator_url}/report_completed", {
                "worker_id": worker_id,
                "count": count
            })
            
    client.close()
    logging.info("Worker Client arrestato correttamente.")

if __name__ == "__main__":
    main()
