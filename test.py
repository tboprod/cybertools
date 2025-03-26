import hashlib
import os
import re
import json
import socket
import requests
from datetime import datetime
import ssl
import cryptography
from cryptography.fernet import Fernet

class CyberSecurityTool:
    def __init__(self):
        self.log_file = 'security_log.txt'
    
    def generate_password_strength_report(self, password):
        """
        Analizza la complessità di una password
        """
        checks = {
            "Lunghezza": len(password) >= 12,
            "Maiuscole": bool(re.search(r'[A-Z]', password)),
            "Minuscole": bool(re.search(r'[a-z]', password)),
            "Numeri": bool(re.search(r'\d', password)),
            "Caratteri Speciali": bool(re.search(r'[!@#$%^&*(),.?":{}|<>]', password)),
        }
        
        strength = sum(checks.values())
        
        return {
            "Password": "*" * len(password),  # Maschera la password
            "Risultati": checks,
            "Punteggio": f"{strength}/5",
            "Valutazione": (
                "Molto Debole" if strength < 2 else
                "Debole" if strength < 3 else
                "Media" if strength < 4 else
                "Forte" if strength < 5 else
                "Molto Forte"
            )
        }
    
    def file_hash_check(self, file_path):
        """
        Calcola gli hash del file per verifica integrità
        """
        try:
            with open(file_path, 'rb') as f:
                file_data = f.read()
                return {
                    "MD5": hashlib.md5(file_data).hexdigest(),
                    "SHA1": hashlib.sha1(file_data).hexdigest(),
                    "SHA256": hashlib.sha256(file_data).hexdigest()
                }
        except FileNotFoundError:
            return {"Errore": "File non trovato"}
    
    def check_ssl_certificate(self, website):
        """
        Verifica i dettagli del certificato SSL
        """
        try:
            # Rimuovi http:// o https:// se presente
            hostname = website.replace('https://', '').replace('http://', '')
            
            # Connessione SSL
            context = ssl.create_default_context()
            with socket.create_connection((hostname, 443)) as sock:
                with context.wrap_socket(sock, server_hostname=hostname) as secure_sock:
                    cert = secure_sock.getpeercert()
                    
                    return {
                        "Sito": website,
                        "Emittente": dict(cert['issuer'])['organizationName'],
                        "Scadenza": cert['notAfter'],
                        "Nome Comune": cert['subject']['commonName']
                    }
        except Exception as e:
            return {"Errore": str(e)}
    
    def basic_file_encryption(self, input_file, output_file=None):
        """
        Crittografia base di un file
        """
        try:
            # Genera una chiave di crittografia
            key = Fernet.generate_key()
            f = Fernet(key)
            
            # Leggi il file
            with open(input_file, 'rb') as file:
                file_data = file.read()
            
            # Crittografa
            encrypted_data = f.encrypt(file_data)
            
            # Nome file di output
            if not output_file:
                output_file = f"{input_file}.encrypted"
            
            # Salva file crittografato
            with open(output_file, 'wb') as file:
                file.write(encrypted_data)
            
            # Salva la chiave (in una situazione reale, la gestiresti diversamente)
            with open(f"{output_file}.key", 'wb') as key_file:
                key_file.write(key)
            
            return {
                "File Originale": input_file,
                "File Crittografato": output_file,
                "Stato": "Crittografia completata"
            }
        except Exception as e:
            return {"Errore": str(e)}
    
    def log_security_event(self, event_type, description):
        """
        Registra un evento di sicurezza
        """
        log_entry = f"{datetime.now()} - {event_type}: {description}\n"
        with open(self.log_file, 'a') as log:
            log.write(log_entry)
        return log_entry

def main():
    security_tool = CyberSecurityTool()
    
    # Test forza password
    print("--- Analisi Complessità Password ---")
    password_tests = [
        "debole",
        "MedioStrong123",
        "!SuperS1curaPassword2024!"
    ]
    
    for pwd in password_tests:
        print(json.dumps(
            security_tool.generate_password_strength_report(pwd), 
            indent=2
        ))
    
    # Verifica hash di un file (se esiste)
    print("\n--- Hash File ---")
    try:
        print(json.dumps(
            security_tool.file_hash_check(__file__), 
            indent=2
        ))
    except Exception as e:
        print(f"Errore nell'analisi hash: {e}")
    
    # Verifica certificato SSL
    print("\n--- Certificato SSL ---")
    print(json.dumps(
        security_tool.check_ssl_certificate('https://www.google.com'), 
        indent=2
    ))
    
    # Log di un evento di sicurezza
    security_tool.log_security_event(
        "SECURITY_CHECK", 
        "Analisi sicurezza completata"
    )

if __name__ == "__main__":
    main()
