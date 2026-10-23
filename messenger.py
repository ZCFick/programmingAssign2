import os
import pickle
import string
from cryptography.hazmat.primitives import hashes, hmac, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.exceptions import InvalidTag

class Certificate():

    def __init__(self, user, pk):
        self.username = user
        self.pk = pk

class MessengerServer:
    def __init__(self, server_signing_key, server_decryption_key):
        self.server_signing_key = server_signing_key
        self.server_decryption_key = server_decryption_key

    def decryptReport(self, ct):
        msg_bytes = ct[:65]
        nonce = ct[65:77]
        body = ct[77:]

        pk = ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256R1(), msg_bytes)
        shared = self.server_decryption_key.exchange(ec.ECDH(), pk)
        key = HKDF(algorithm=hashes.SHA256(), length=32, salt=None, info=b"report" + msg_bytes).derive(shared)

        return AESGCM(key).decrypt(nonce, body, None).decode()

    def signCert(self, cert):
        cert = pickle.dumps(cert)
        return self.server_signing_key.sign(cert, ec.ECDSA(hashes.SHA256()))

class MessengerClient:

    def __init__(self, name, server_signing_pk, server_encryption_pk):
        self.name = name
        self.server_signing_pk = server_signing_pk
        self.server_encryption_pk = server_encryption_pk
        self.conns = {}
        self.certs = {}

    def generateCertificate(self):
        self.dh_sk = ec.generate_private_key(ec.SECP256R1())
        pk_bytes = self.dh_sk.public_key().public_bytes(serialization.Encoding.X962,serialization.PublicFormat.UncompressedPoint)
        return Certificate(self.name, pk_bytes)

    def receiveCertificate(self, certificate, signature):
        cert_bytes = pickle.dumps(certificate)
        self.server_signing_pk.verify(signature, cert_bytes, ec.ECDSA(hashes.SHA256()))
        pk = ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256R1(), certificate.pk)
        self.certs[certificate.username] = pk
        return

    def sendMessage(self, name, message):
        message = message.encode()
        if (name not in self.conns):
            partner_pk = self.certs[name]
            state = {
            "RK": self.dh_sk.exchange(ec.ECDH(), partner_pk),
            "DHs": self.dh_sk,
            "DHr": partner_pk,
            "CKr": None,
            "CKs": None,
            "Ns": 0, "Nr": 0, "PN": 0
            }
            new_sk = ec.generate_private_key(ec.SECP256R1())
            dh_out = new_sk.exchange(ec.ECDH(), state["DHr"])
            out = HKDF(algorithm=hashes.SHA256(), length=64, salt=state["RK"], info=b"ratchet").derive(dh_out)
            state["RK"], state["CKs"] = out[:32], out[32:]
            state["DHs"] = new_sk

            self.conns[name] = state

        state = self.conns[name]

        h = hmac.HMAC(state["CKs"], hashes.SHA256())
        h.update(b"\x01")
        msg_key = h.finalize()

        h = hmac.HMAC(state["CKs"], hashes.SHA256())
        h.update(b"\x02")
        state["CKs"] = h.finalize()

        header = (state["DHs"].public_key().public_bytes(serialization.Encoding.X962, serialization.PublicFormat.UncompressedPoint) + state["PN"].to_bytes(4, "big") + state["Ns"].to_bytes(4, "big"))

        nonce = os.urandom(12)
        ciphertext = nonce + AESGCM(msg_key).encrypt(nonce, message, header)

        state["Ns"] += 1
        return header, ciphertext

    def receiveMessage(self, name, header, ciphertext):
        # Reject non-bytes inputs, incorrect header length, or truncated ciphertexts
        if not isinstance(header, (bytes, bytearray)) or len(header) != 73:
            return None
        if not isinstance(ciphertext, (bytes, bytearray)) or len(ciphertext) < 12:
            return None

        if name in self.conns:
            state = self.conns[name]
        else:
            if name not in self.certs:
                return None
            state = {
                "RK": self.dh_sk.exchange(ec.ECDH(), self.certs[name]),
                "DHs": self.dh_sk,
                "DHr": None,
                "CKr": None,
                "CKs": None,
                "Ns": 0, "Nr": 0, "PN": 0
            }

        header_pk = header[:65]
        PN = int.from_bytes(header[65:69], "big")
        msg_num = int.from_bytes(header[69:73], "big")

        try:
            known_pk = None
            if state["DHr"] is not None:
                known_pk = state["DHr"].public_bytes(
                    serialization.Encoding.X962,
                    serialization.PublicFormat.UncompressedPoint
                )

            if header_pk != known_pk:
                if state["CKr"] is not None and PN != state["Nr"]:
                    return None

                new_remote = ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256R1(), header_pk)
                dh_out = state["DHs"].exchange(ec.ECDH(), new_remote)
                out = HKDF(algorithm=hashes.SHA256(), length=64, salt=state["RK"], info=b"ratchet").derive(dh_out)
                state["RK"], state["CKr"] = out[:32], out[32:]
                state["DHr"] = new_remote
                state["Nr"] = 0

                state["PN"] = state["Ns"]
                state["Ns"] = 0
                new_sk = ec.generate_private_key(ec.SECP256R1())
                dh_out = new_sk.exchange(ec.ECDH(), state["DHr"])
                out = HKDF(algorithm=hashes.SHA256(), length=64, salt=state["RK"], info=b"ratchet").derive(dh_out)
                state["RK"], state["CKs"] = out[:32], out[32:]
                state["DHs"] = new_sk

            if state["CKr"] is None or msg_num != state["Nr"]:
                return None

            h = hmac.HMAC(state["CKr"], hashes.SHA256())
            h.update(b"\x01")
            msg_key = h.finalize()

            h = hmac.HMAC(state["CKr"], hashes.SHA256())
            h.update(b"\x02")
            state["CKr"] = h.finalize()

            nonce = ciphertext[:12]
            body = ciphertext[12:]

            message = AESGCM(msg_key).decrypt(nonce, body, header)
            state["Nr"] += 1
            self.conns[name] = state
            return message.decode("utf-8")

        except (InvalidTag, TypeError, ValueError, UnicodeDecodeError):
            return None

    def report(self, name, message):
        plaintext = "User: " + name + "\nMessage: " + message

        sk = ec.generate_private_key(ec.SECP256R1())
        msg_bytes = sk.public_key().public_bytes(serialization.Encoding.X962, serialization.PublicFormat.UncompressedPoint)
        shared = sk.exchange(ec.ECDH(), self.server_encryption_pk)
        key = HKDF(algorithm=hashes.SHA256(), length=32, salt=None, info=b"report" + msg_bytes).derive(shared)

        nonce = os.urandom(12)

        ct = msg_bytes + nonce + AESGCM(key).encrypt(nonce, plaintext.encode(), None)
        return plaintext, ct
