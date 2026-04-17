# ============================================================
#                    SecureChat - ClientA
# ============================================================
#  Secure Peer-to-Peer Chat System
#
#  Security Features:
#  - RSA Identity Keys + CA Signed Certificates
#  - Certificate Revocation Check
#  - ECDHE Ephemeral Key Exchange (Forward Secrecy)
#  - HKDF Key Derivation
#  - AES-GCM Authenticated Encryption
#  - Replay Protection via Counters
#  - Explicit Key Confirmation (HMAC)
#  - Automatic Time-Based Rekeying
#  - Secure Chunked File Transfer (Size Limited)
# ============================================================


# =========================
# Standard Library Imports
# =========================

import os
import sys
import time
import socket
import struct
import select
import threading
import datetime
import termios
import tty


# =========================
# Cryptography Imports
# =========================

from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes, serialization, hmac
from cryptography.hazmat.primitives.asymmetric import rsa, padding, ec
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.ciphers.aead import AESGCM


# ============================================================
#                       CONFIGURATION
# ============================================================

CLIENT_NAME = "ClientA"

CA_HOST = "127.0.0.1"
CA_PORT = 8000

HOST = "127.0.0.1"
PORT = 9000

MAX_FRAME_SIZE = 64 * 1024
FILE_CHUNK_SIZE = 60 * 1024
MAX_FILE_SIZE = 200 * 1024 * 1024

REKEY_AFTER_SECONDS = 120


# ============================================================
#                    GLOBAL STATE VARIABLES
# ============================================================

SEND_COUNTER = 0
RECV_COUNTER = 0

SEND_KEY = None
RECV_KEY = None

SEND_NONCE_BASE = None
RECV_NONCE_BASE = None

last_rekey_time = time.time()

active_connection = None


# ============================================================
#                       FILE PATHS
# ============================================================

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
KEY_FILE = os.path.join(BASE_DIR, "A_key.pem")
CERT_FILE = os.path.join(BASE_DIR, "A_cert.pem")
CA_CERT_FILE = os.path.join(BASE_DIR, "../shared/ca_certificate.pem")


# ============================================================
#                           UI
# ============================================================

def print_banner():
    """
    Displays startup banner and connection status.
    """
    print("\n" + "=" * 35)
    print("        SecureChat - ClientA")
    print("=" * 35)
    print(f"Status : Listening on {HOST}:{PORT}")
    print("-" * 35)


# ============================================================
#                       FRAMING LAYER
# ============================================================

def send_framed(sock, data):
    """
    Sends data with a 4-byte length prefix.
    Ensures receiver knows exactly how many bytes to read.
    """
    sock.sendall(struct.pack("!I", len(data)) + data)


def recv_framed(sock):
    """
    Receives length-prefixed framed data.
    Protects against oversized frames.
    """
    raw_len = sock.recv(4)
    if not raw_len:
        return None

    length = struct.unpack("!I", raw_len)[0]

    if length > MAX_FRAME_SIZE:
        print("Frame too large. Closing connection.")
        sock.close()
        return None

    data = b""
    while len(data) < length:
        packet = sock.recv(length - len(data))
        if not packet:
            return None
        data += packet

    return data


# ============================================================
#                 KEY GENERATION & CERTIFICATES
# ============================================================

def generate_key():
    """
    Generates RSA identity key (2048-bit) for the client.
    Stored locally as PEM file.
    """
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048
    )

    with open(KEY_FILE, "wb") as f:
        f.write(private_key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.TraditionalOpenSSL,
            serialization.NoEncryption()
        ))


def create_csr():
    """
    Creates Certificate Signing Request (CSR)
    containing identity information.
    """
    with open(KEY_FILE, "rb") as f:
        private_key = serialization.load_pem_private_key(f.read(), None)

    subject = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, "IN"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "SecureChat"),
        x509.NameAttribute(NameOID.COMMON_NAME, CLIENT_NAME),
    ])

    csr = x509.CertificateSigningRequestBuilder() \
        .subject_name(subject) \
        .sign(private_key, hashes.SHA256())

    return csr.public_bytes(serialization.Encoding.PEM)


def request_certificate():
    """
    Sends CSR to Certificate Authority (CA)
    and receives signed certificate.
    """
    csr = create_csr()

    s = socket.socket()
    s.connect((CA_HOST, CA_PORT))
    s.sendall(csr)

    cert = s.recv(8192)

    with open(CERT_FILE, "wb") as f:
        f.write(cert)

    s.close()
    print("Certificate received from CA.")


def is_revoked(serial_number):
    """
    Checks if a certificate serial number
    exists in local revocation list.
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


def verify_certificate(peer_cert_data, expected_name):
    """
    Verifies:
    - Signature by CA
    - Not revoked
    - Not expired
    - Not a CA certificate
    - Expected identity matches
    """
    peer_cert = x509.load_pem_x509_certificate(peer_cert_data)

    if is_revoked(peer_cert.serial_number):
        raise Exception("Certificate revoked")

    with open(CA_CERT_FILE, "rb") as f:
        ca_cert = x509.load_pem_x509_certificate(f.read())

    # Verify CA signature
    ca_cert.public_key().verify(
        peer_cert.signature,
        peer_cert.tbs_certificate_bytes,
        padding.PKCS1v15(),
        peer_cert.signature_hash_algorithm
    )

    # Ensure peer is not a CA
    if peer_cert.extensions.get_extension_for_class(
        x509.BasicConstraints
    ).value.ca:
        raise Exception("Peer cannot be CA")

    # Validity period check
    from datetime import datetime, timezone
    now = datetime.now(timezone.utc)

    if now < peer_cert.not_valid_before_utc:
        raise Exception("Certificate not yet valid")

    if now > peer_cert.not_valid_after_utc:
        raise Exception("Certificate expired")

    # Identity verification
    cn = peer_cert.subject.get_attributes_for_oid(
        NameOID.COMMON_NAME
    )[0].value

    if cn != expected_name:
        raise Exception("Unexpected peer identity")

    print(f"Certificate verified for {cn}")
    return peer_cert


# ============================================================
#                  SECURE KEY EXCHANGE (ECDHE)
# ============================================================

def secure_key_exchange(sock, peer_cert):
    """
    Performs:
    - Ephemeral ECDH key generation
    - RSA signature authentication
    - Shared secret derivation
    - HKDF master key generation
    - Directional key splitting
    - Nonce base derivation
    - Explicit key confirmation (HMAC)
    """
    global SEND_KEY, RECV_KEY, SEND_NONCE_BASE, RECV_NONCE_BASE

    # Generate ephemeral ECDH key pair
    private_ec = ec.generate_private_key(ec.SECP256R1())
    public_ec = private_ec.public_key()

    pub_bytes = public_ec.public_bytes(
        serialization.Encoding.PEM,
        serialization.PublicFormat.SubjectPublicKeyInfo
    )

    # Sign ephemeral key with RSA identity key
    with open(KEY_FILE, "rb") as f:
        rsa_private = serialization.load_pem_private_key(f.read(), None)

    signature = rsa_private.sign(
        pub_bytes,
        padding.PKCS1v15(),
        hashes.SHA256()
    )

    # Exchange keys
    send_framed(sock, pub_bytes)
    send_framed(sock, signature)

    peer_pub = recv_framed(sock)
    peer_sig = recv_framed(sock)

    # Verify peer signature
    peer_cert.public_key().verify(
        peer_sig,
        peer_pub,
        padding.PKCS1v15(),
        hashes.SHA256()
    )

    peer_ec = serialization.load_pem_public_key(peer_pub)
    shared = private_ec.exchange(ec.ECDH(), peer_ec)

    # Salt exchange
    local_salt = os.urandom(16)
    send_framed(sock, local_salt)
    peer_salt = recv_framed(sock)

    # Transcript binding
    items = [pub_bytes, signature, peer_pub, peer_sig, local_salt, peer_salt]
    transcript_hash_obj = hashes.Hash(hashes.SHA256())
    transcript_hash_obj.update(b"".join(sorted(items)))
    transcript_hash = transcript_hash_obj.finalize()

    combined = local_salt + peer_salt if local_salt < peer_salt else peer_salt + local_salt

    digest = hashes.Hash(hashes.SHA256())
    digest.update(combined)
    final_salt = digest.finalize()

    # Derive 64-byte master key
    master_key = HKDF(
        algorithm=hashes.SHA256(),
        length=64,
        salt=final_salt,
        info=transcript_hash
    ).derive(shared)

    # Split into directional keys
    SEND_KEY = master_key[:32]
    RECV_KEY = master_key[32:]

    # Derive nonce bases
    def derive_nonce_base(key):
        return HKDF(
            algorithm=hashes.SHA256(),
            length=12,
            salt=None,
            info=b"nonce-base"
        ).derive(key)

    SEND_NONCE_BASE = derive_nonce_base(SEND_KEY)
    RECV_NONCE_BASE = derive_nonce_base(RECV_KEY)

    # Explicit key confirmation
    h = hmac.HMAC(master_key, hashes.SHA256())
    h.update(transcript_hash)
    my_confirm = h.finalize()

    send_framed(sock, my_confirm)
    peer_confirm = recv_framed(sock)

    h2 = hmac.HMAC(master_key, hashes.SHA256())
    h2.update(transcript_hash)
    h2.verify(peer_confirm)

    print("Secure session key established.")

# ============================================================
#                           REKEY
# ============================================================

def perform_rekey(sock, peer_cert):
    global SEND_COUNTER, RECV_COUNTER, last_rekey_time

    print("\n🔄 Performing fresh ECDH rekey...\n")

    secure_key_exchange(sock, peer_cert)

    SEND_COUNTER = 0
    RECV_COUNTER = 0
    last_rekey_time = time.time()

    print("\n🔄 Fresh session key established.\n")


def send_control(sock, message):
    global SEND_COUNTER

    aesgcm = AESGCM(SEND_KEY)

    counter_bytes = struct.pack("!Q", SEND_COUNTER)
    counter_int = int.from_bytes(counter_bytes, "big")

    nonce_int = int.from_bytes(SEND_NONCE_BASE, "big") ^ counter_int
    nonce = nonce_int.to_bytes(12, "big")

    counter_bytes = struct.pack("!Q", SEND_COUNTER)
    SEND_COUNTER += 1

    ciphertext = aesgcm.encrypt(
        nonce,
        message.encode(),
        counter_bytes
    )

    send_framed(sock, counter_bytes + nonce + ciphertext)


def rekey_timer(sock):
    global last_rekey_time

    while True:
        time.sleep(1)

        if time.time() - last_rekey_time >= REKEY_AFTER_SECONDS:
            print("\n🔄 Automatic time-based rekey triggered.")
            send_control(sock, "CONTROL:REKEY")
            last_rekey_time = time.time()


# ============================================================
#                        RECEIVE LOOP
# ============================================================

def receive_loop(sock, peer_cert):
    global RECV_COUNTER

    receiving_file = None
    file_handle = None
    bytes_received = 0

    while True:
        try:
            data = recv_framed(sock)
            if not data:
                return
        except:
            return

        counter_bytes = data[:8]
        counter_int = int.from_bytes(counter_bytes, "big")

        nonce_int = int.from_bytes(RECV_NONCE_BASE, "big") ^ counter_int
        nonce = nonce_int.to_bytes(12, "big")

        ciphertext = data[20:]
        received_counter = struct.unpack("!Q", counter_bytes)[0]

        if received_counter != RECV_COUNTER:
            print("⚠ Replay or out-of-order message detected!")
            continue

        aesgcm = AESGCM(RECV_KEY)

        try:
            plaintext = aesgcm.decrypt(
                nonce,
                ciphertext,
                counter_bytes
            )
        except:
            continue

        RECV_COUNTER += 1

        # -----------------------------
        # Rekey Handling
        # -----------------------------

        if plaintext == b"CONTROL:REKEY":
            print("🔄 Rekey request received.")
            send_control(sock, "CONTROL:REKEY-ACK")
            perform_rekey(sock, peer_cert)
            continue

        if plaintext == b"CONTROL:REKEY-ACK":
            print("🔄 Rekey acknowledged.")
            perform_rekey(sock, peer_cert)
            continue

        message = plaintext.decode(errors="ignore")

        # -----------------------------
        # File Transfer Handling
        # -----------------------------

        if message.startswith("FILE_START:"):
            filename = message.split(":", 1)[1]
            receiving_file = "received_" + filename
            file_handle = open(receiving_file, "wb")
            print(f"\n[+] Receiving file: {filename}")
            continue

        if plaintext.startswith(b"FILE_CHUNK:"):
            chunk = plaintext[len(b"FILE_CHUNK:"):]

            if file_handle:
                bytes_received += len(chunk)

                if bytes_received > MAX_FILE_SIZE:
                    print("⚠ File size limit exceeded. Aborting transfer.")
                    file_handle.close()
                    os.remove(receiving_file)
                    sock.close()
                    return

                file_handle.write(chunk)

            continue

        if message == "FILE_END":
            if file_handle:
                file_handle.close()
                print(f"[+] File saved as {receiving_file}")

            receiving_file = None
            file_handle = None
            continue

        # -----------------------------
        # Normal Chat Message
        # -----------------------------

        print(f"\n[Peer]: {message}")


# ============================================================
#                          FILE SEND
# ============================================================

def send_file(sock, filename):
    global SEND_COUNTER, last_rekey_time

    if not os.path.exists(filename):
        print("File not found.")
        return

    basename = os.path.basename(filename)
    last_rekey_time = time.time()

    # ---- FILE START ----
    send_control(sock, f"FILE_START:{basename}")

    aesgcm = AESGCM(SEND_KEY)

    with open(filename, "rb") as f:
        while True:
            chunk = f.read(FILE_CHUNK_SIZE)
            if not chunk:
                break

            payload = b"FILE_CHUNK:" + chunk

            counter_bytes = struct.pack("!Q", SEND_COUNTER)
            counter_int = int.from_bytes(counter_bytes, "big")

            nonce_int = int.from_bytes(SEND_NONCE_BASE, "big") ^ counter_int
            nonce = nonce_int.to_bytes(12, "big")

            ciphertext = aesgcm.encrypt(
                nonce,
                payload,
                counter_bytes
            )

            send_framed(sock, counter_bytes + nonce + ciphertext)

            SEND_COUNTER += 1

    # ---- FILE END ----
    send_control(sock, "FILE_END")

    print(f"[+] File '{basename}' sent successfully.")


# ============================================================
#                           CHAT
# ============================================================

def start_chat(sock, peer_cert):
    global SEND_COUNTER

    print("\n🔐 Secure chat started (type 'exit' to quit)\n")

    my_cert = x509.load_pem_x509_certificate(
        open(CERT_FILE, "rb").read()
    )

    my_cn = my_cert.subject.get_attributes_for_oid(
        NameOID.COMMON_NAME
    )[0].value

    peer_cn = peer_cert.subject.get_attributes_for_oid(
        NameOID.COMMON_NAME
    )[0].value

    IS_REKEY_LEADER = my_cn < peer_cn

    threading.Thread(
        target=receive_loop,
        args=(sock, peer_cert),
        daemon=True
    ).start()

    if IS_REKEY_LEADER:
        print("🔹 I am Rekey Leader")
        threading.Thread(
            target=rekey_timer,
            args=(sock,),
            daemon=True
        ).start()
    else:
        print("🔹 I am Rekey Follower")

    while True:
        msg = input()

        if msg.lower() == "exit":
            sock.close()
            break

        if msg.startswith("/sendfile "):
            filename = msg.split(" ", 1)[1]
            send_file(sock, filename)
            continue

        if msg == "":
            continue

        aesgcm = AESGCM(SEND_KEY)

        counter_bytes = struct.pack("!Q", SEND_COUNTER)
        counter_int = int.from_bytes(counter_bytes, "big")

        nonce_int = int.from_bytes(SEND_NONCE_BASE, "big") ^ counter_int
        nonce = nonce_int.to_bytes(12, "big")

        ciphertext = aesgcm.encrypt(
            nonce,
            msg.encode(),
            counter_bytes
        )

        send_framed(sock, counter_bytes + nonce + ciphertext)

        SEND_COUNTER += 1

        print(f"[Me - {CLIENT_NAME}]: {msg}")


# ============================================================
#                    CONNECTION MANAGEMENT
# ============================================================

def listen_for_connections():
    global active_connection, SEND_COUNTER, RECV_COUNTER

    server = socket.socket()
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.bind((HOST, PORT))
    server.listen(1)

    while True:
        conn, _ = server.accept()

        if active_connection:
            conn.close()
            continue

        active_connection = conn

        print("\n[A] Incoming connection received.")
        print("[A] Receiving peer certificate...")

        peer_cert = verify_certificate(
            recv_framed(conn),
            "ClientB"
        )

        print("[A] Sending my certificate...")
        send_framed(conn, open(CERT_FILE, "rb").read())

        secure_key_exchange(conn, peer_cert)

        SEND_COUNTER = 0
        RECV_COUNTER = 0

        start_chat(conn, peer_cert)
        return


def connect_to_B():
    global active_connection, SEND_COUNTER, RECV_COUNTER

    print("[A] Connecting to ClientB...")

    s = socket.socket()
    active_connection = s

    s.connect(("127.0.0.1", 9001))

    print("[A] Sending my certificate...")
    send_framed(s, open(CERT_FILE, "rb").read())

    print("[A] Receiving peer certificate...")
    peer_cert = verify_certificate(
        recv_framed(s),
        "ClientB"
    )

    secure_key_exchange(s, peer_cert)

    SEND_COUNTER = 0
    RECV_COUNTER = 0

    start_chat(s, peer_cert)


# ============================================================
#                           MAIN
# ============================================================

if __name__ == "__main__":

    if not os.path.exists(KEY_FILE):
        print("[A] Generating RSA key...")
        generate_key()
    else:
        print("[A] RSA key already present.")

    if not os.path.exists(CERT_FILE):
        print("[A] Requesting certificate from CA...")
        request_certificate()
    else:
        print("[A] Certificate already present.")

    threading.Thread(
        target=listen_for_connections,
        daemon=True
    ).start()

    while True:

        if active_connection:
            time.sleep(1)
            continue

        print_banner()

        print("1. Connect to ClientB")
        print("2. Exit")
        print("-" * 35)

        choice = input("Enter choice: ")

        if choice == "1":
            connect_to_B()

        elif choice == "2":
            print("[A] Exiting SecureChat.")
            break
