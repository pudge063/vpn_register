from fastapi import FastAPI, HTTPException
import subprocess
import os

from starlette.responses import FileResponse

app = FastAPI()

CERT_DIR = "/etc/ipsec.d/certs/"
KEY_DIR = "/etc/ipsec.d/private/"
CA_CERT = "/etc/ipsec.d/certs/ca-cert.pem"
CA_KEY = "/etc/ipsec.d/private/ca-key.pem"

@app.post("/generate_certificate/{username}")
def generate_certificate(username: str):
    # Пути для хранения сертификата и ключа пользователя
    client_cert = os.path.join(CERT_DIR, f"client-cert-{username}.pem")
    client_key = os.path.join(KEY_DIR, f"client-key-{username}.pem")

    # Генерация ключа клиента
    key_gen_command = f"ipsec pki --gen --outform pem > {client_key}"
    key_gen_result = subprocess.run(key_gen_command, shell=True, capture_output=True)
    if key_gen_result.returncode != 0:
        raise HTTPException(status_code=500, detail="Error generating client key")

    # Генерация сертификата клиента
    cert_gen_command = (
        f"ipsec pki --pub --in {client_key} | "
        f"ipsec pki --issue --lifetime 14 --cacert {CA_CERT} --cakey {CA_KEY} "
        f"--dn 'CN={username}' --outform pem > {client_cert}"
    )
    cert_gen_result = subprocess.run(cert_gen_command, shell=True, capture_output=True)
    if cert_gen_result.returncode != 0:
        raise HTTPException(status_code=500, detail="Error generating client certificate")

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
