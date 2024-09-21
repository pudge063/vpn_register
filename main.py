from fastapi import FastAPI, HTTPException
import subprocess
import os
import logging
from starlette.responses import FileResponse

# Настройка логирования
logging.basicConfig(level=logging.INFO)

app = FastAPI()

CERT_DIR = "/etc/ipsec.d/certs/"
KEY_DIR = "/etc/ipsec.d/private/"
CA_CERT = "/etc/ipsec.d/certs/ca-cert.pem"
CA_KEY = "/etc/ipsec.d/private/ca-key.pem"

@app.post("/generate_certificate/{username}")
def generate_certificate(username: str):
    client_cert = os.path.join(CERT_DIR, f"client-cert-{username}.pem")
    client_key = os.path.join(KEY_DIR, f"client-key-{username}.pem")

    try:
        # Генерация ключа клиента
        key_gen_command = ["/usr/sbin/ipsec", "pki", "--gen", "--outform", "pem"]
        with open(client_key, "wb") as key_file:
            key_gen_result = subprocess.run(key_gen_command, stdout=key_file, stderr=subprocess.PIPE, check=True)

        logging.info(f"Client key generated at: {client_key}")

        # Генерация публичного ключа
        pub_key_command = ["/usr/sbin/ipsec", "pki", "--pub", "--in", client_key]
        pub_key_result = subprocess.run(pub_key_command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=True)

        # Генерация сертификата клиента
        cert_gen_command = [
            "/usr/sbin/ipsec", "pki", "--issue",
            "--lifetime", "14",
            "--cacert", CA_CERT,
            "--cakey", CA_KEY,
            "--dn", f"CN={username}",
            "--outform", "pem"
        ]

        with open(client_cert, "wb") as cert_file:
            cert_gen_result = subprocess.run(cert_gen_command, input=pub_key_result.stdout, stdout=cert_file, stderr=subprocess.PIPE, check=True)

        logging.info(f"Client certificate generated at: {client_cert}")

    except subprocess.CalledProcessError as e:
        logging.error(f"Error during certificate generation: {e.stderr.decode().strip()}")
        raise HTTPException(status_code=500, detail=f"Error generating client key or certificate: {e.stderr.decode().strip()}")

    return {"message": "Certificate generated", "cert_path": client_cert, "key_path": client_key}

@app.get("/download_cert/{username}")
def download_cert(username: str):
    cert_path = os.path.join(CERT_DIR, f"client-cert-{username}.pem")
    if not os.path.exists(cert_path):
        raise HTTPException(status_code=404, detail="Certificate not found")
    return FileResponse(cert_path, media_type="application/x-pem-file", filename=f"client-cert-{username}.pem")

@app.get("/download_key/{username}")
def download_key(username: str):
    key_path = os.path.join(KEY_DIR, f"client-key-{username}.pem")
    if not os.path.exists(key_path):
        raise HTTPException(status_code=404, detail="Key not found")
    return FileResponse(key_path, media_type="application/x-pem-file", filename=f"client-key-{username}.pem")
