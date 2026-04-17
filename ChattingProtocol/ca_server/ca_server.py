# ============================================================
#                SecureChat - Certificate Authority
# ============================================================
#
#  Responsibilities:
#  - Generate Root CA (if not exists)
#  - Issue certificates to authorized clients
#  - Maintain revocation list
#  - Distribute CA certificate to shared folder
#
#  This CA acts as a trusted third party that:
#  - Signs client CSRs
#  - Establishes trust anchor
# ============================================================


# =========================
# Standard Library Imports
# =========================

import socket
import datetime
import os
import shutil


# =========================
# Cryptography Imports
# =========================

from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa


# ============================================================
#                       CONFIGURATION
# ============================================================

HOST = "127.0.0.1"
PORT = 8000

BASE_DIR = os.path.dirname(os.path.abspath(__file__))

CA_KEY_FILE = os.path.join(BASE_DIR, "ca_private_key.pem")
CA_CERT_FILE = os.path.join(BASE_DIR, "ca_certificate.pem")
REVOKED_FILE = os.path.join(BASE_DIR, "revoked_serials.txt")

SHARED_DIR = os.path.join(BASE_DIR, "../shared")
SHARED_CA_CERT = os.path.join(SHARED_DIR, "ca_certificate.pem")


# ============================================================
#                  ROOT CA GENERATION
# ============================================================

def generate_ca():
    """
    Generates Root Certificate Authority (CA) if not already present.

    Steps:
    - Generate RSA private key
    - Create self-signed certificate
    - Store private key securely (password protected)
    - Store CA certificate
    - Ensure revocation file exists
    - Copy CA certificate to shared folder
    """

    # If CA already exists, skip regeneration
    if os.path.exists(CA_KEY_FILE) and os.path.exists(CA_CERT_FILE):
        print("[+] CA already exists.")
    else:
        print("[+] Generating CA private key...")

        # Step 1: Generate RSA private key
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048
        )

        # Step 2: Define CA subject/issuer (self-signed)
        subject = issuer = x509.Name([
            x509.NameAttribute(NameOID.COUNTRY_NAME, "IN"),
            x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, "Jammu & Kashmir"),
            x509.NameAttribute(NameOID.LOCALITY_NAME, "IIT Jammu"),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "SecureChat CA"),
            x509.NameAttribute(NameOID.COMMON_NAME, "SecureChat Root CA"),
        ])

        print("[+] Creating self-signed CA certificate...")

        # Step 3: Build self-signed certificate
        cert = (
            x509.CertificateBuilder()
            .subject_name(subject)
            .issuer_name(issuer)
            .public_key(private_key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(datetime.datetime.utcnow())
            .not_valid_after(
                datetime.datetime.utcnow() + datetime.timedelta(days=3650)
            )
            .add_extension(
                x509.BasicConstraints(ca=True, path_length=None),
                critical=True
            )
            .add_extension(
                x509.SubjectKeyIdentifier.from_public_key(
                    private_key.public_key()
                ),
                critical=False
            )
            .add_extension(
                x509.AuthorityKeyIdentifier.from_issuer_public_key(
                    private_key.public_key()
                ),
                critical=False
            )
            .sign(private_key, hashes.SHA256())
        )

        # Step 4: Save encrypted private key
        with open(CA_KEY_FILE, "wb") as f:
            f.write(
                private_key.private_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PrivateFormat.TraditionalOpenSSL,
                    encryption_algorithm=serialization.BestAvailableEncryption(
                        b"StrongCAPassword123"
                    )
                )
            )

        # Step 5: Save CA certificate
        with open(CA_CERT_FILE, "wb") as f:
            f.write(cert.public_bytes(serialization.Encoding.PEM))

        print("[+] Root CA generated successfully.")

    # Ensure revocation file exists
    if not os.path.exists(REVOKED_FILE):
        open(REVOKED_FILE, "w").close()

    # Always copy CA certificate to shared directory
    copy_ca_cert_to_shared()


# ============================================================
#             COPY CA CERTIFICATE TO SHARED FOLDER
# ============================================================

def copy_ca_cert_to_shared():
    """
    Copies CA certificate to shared folder
    so clients can verify peer certificates.
    """

    if not os.path.exists(SHARED_DIR):
        os.makedirs(SHARED_DIR)

    shutil.copyfile(CA_CERT_FILE, SHARED_CA_CERT)
    print("[+] CA certificate copied to shared folder.")


# ============================================================
#               SIGN CSR AND ISSUE CERTIFICATE
# ============================================================

def sign_csr(csr_data):
    """
    Signs client CSR and issues certificate.

    Steps:
    - Load CA private key
    - Load CA certificate
    - Parse CSR
    - Issue client certificate (valid 1 year)
    """

    # Load CA private key (password protected)
    with open(CA_KEY_FILE, "rb") as f:
        ca_private_key = serialization.load_pem_private_key(
            f.read(),
            password=b"StrongCAPassword123"
        )

    # Load CA certificate
    with open(CA_CERT_FILE, "rb") as f:
        ca_cert = x509.load_pem_x509_certificate(f.read())

    csr = x509.load_pem_x509_csr(csr_data)

    # Build client certificate
    cert = (
        x509.CertificateBuilder()
        .subject_name(csr.subject)
        .issuer_name(ca_cert.subject)
        .public_key(csr.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.datetime.utcnow())
        .not_valid_after(
            datetime.datetime.utcnow() + datetime.timedelta(days=365)
        )
        .add_extension(
            x509.BasicConstraints(ca=False, path_length=None),
            critical=True
        )
        .add_extension(
            x509.SubjectKeyIdentifier.from_public_key(csr.public_key()),
            critical=False
        )
        .add_extension(
            x509.AuthorityKeyIdentifier.from_issuer_public_key(
                ca_private_key.public_key()
            ),
            critical=False
        )
        .sign(ca_private_key, hashes.SHA256())
    )

    print(f"[+] Issued certificate serial: {cert.serial_number}")

    return cert.public_bytes(serialization.Encoding.PEM)


# ============================================================
#                         CA SERVER
# ============================================================

def start_server():
    """
    Starts CA TCP server.

    - Accepts CSR requests
    - Validates client identity
    - Signs and returns certificate
    """

    generate_ca()

    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.bind((HOST, PORT))
    server.listen(5)

    print(f"[+] CA Server listening on {HOST}:{PORT}")

    while True:
        client_socket, addr = server.accept()
        client_socket.settimeout(5)

        print(f"[+] Connection from {addr}")

        csr_data = client_socket.recv(8192)

        csr = x509.load_pem_x509_csr(csr_data)

        # Extract Common Name (CN)
        cn = csr.subject.get_attributes_for_oid(
            NameOID.COMMON_NAME
        )[0].value

        # Allow only known clients
        allowed_clients = ["ClientA", "ClientB"]

        if cn not in allowed_clients:
            print(f"Unauthorized CSR request from CN: {cn}")
            client_socket.close()
            continue

        print(f"[+] CSR received from authorized client: {cn}")
        print("[+] Signing certificate...")

        signed_cert = sign_csr(csr_data)

        client_socket.sendall(signed_cert)
        client_socket.close()

        print("[+] Certificate issued.\n")


# ============================================================
#                      REVOCATION CHECK
# ============================================================

def is_revoked(serial_number):
    """
    Checks if a certificate serial number
    exists in revocation list.
    """

    revoked_path = os.path.join(
        os.path.dirname(CA_CERT_FILE),
        "revoked_serials.txt"
    )

    if not os.path.exists(revoked_path):
        return False

    with open(revoked_path, "r") as f:
        revoked = f.read().splitlines()

    return str(serial_number) in revoked


# ============================================================
#                           MAIN
# ============================================================

if __name__ == "__main__":
    """
    Entry point of Certificate Authority server.
    """
    start_server()
