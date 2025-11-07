from flask import Flask, request, jsonify, send_file, make_response, Response
from flask_cors import CORS
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.PublicKey import RSA
from Crypto.Random import get_random_bytes
from cryptography.fernet import Fernet
import base64
import os
import json
import traceback
import mimetypes

app = Flask(__name__)
CORS(app, expose_headers=["X-Encryption-Key"])

# Folders
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
UPLOAD_FOLDER = os.path.join(BASE_DIR, "uploads")
ENCRYPTED_FOLDER = os.path.join(BASE_DIR, "encrypted")
DECRYPTED_FOLDER = os.path.join(BASE_DIR, "decrypted")
os.makedirs(UPLOAD_FOLDER, exist_ok=True)
os.makedirs(ENCRYPTED_FOLDER, exist_ok=True)
os.makedirs(DECRYPTED_FOLDER, exist_ok=True)


def _pack_with_metadata(original_filename: str, ciphertext: bytes, extra: bytes = b"") -> bytes:
    """
    Pack metadata + extra + ciphertext:
      4 bytes: metadata length (big-endian)
      metadata JSON bytes
      4 bytes: extra length (big-endian)
      extra bytes
      remaining: ciphertext
    """
    metadata = {"original_filename": original_filename}
    metadata_json = json.dumps(metadata).encode("utf-8")
    meta_len = len(metadata_json).to_bytes(4, "big")
    extra_len = len(extra).to_bytes(4, "big")
    return meta_len + metadata_json + extra_len + extra + ciphertext


def _unpack_with_metadata(packed: bytes):
    """
    Returns (original_filename, extra_bytes, ciphertext_bytes)
    """
    if len(packed) < 8:
        raise ValueError("Packed data too short to contain metadata.")
    meta_len = int.from_bytes(packed[:4], "big")
    if len(packed) < 4 + meta_len + 4:
        raise ValueError("Packed data too short for indicated metadata length.")
    metadata_json = packed[4:4 + meta_len]
    meta = json.loads(metadata_json.decode("utf-8"))
    cursor = 4 + meta_len
    extra_len = int.from_bytes(packed[cursor:cursor + 4], "big")
    cursor += 4
    extra = packed[cursor:cursor + extra_len]
    cursor += extra_len
    ciphertext = packed[cursor:]
    return meta.get("original_filename", "restored_file"), extra, ciphertext


@app.route("/encrypt", methods=["POST"])
def encrypt_endpoint():
    try:
        file = request.files.get("file")
        method = request.form.get("method", "AES")
        if not file:
            return jsonify({"error": "No file uploaded"}), 400

        original_name = file.filename
        data = file.read()

        # AES-GCM (symmetric)
        if method == "AES":
            aes_key = get_random_bytes(32)  # 256-bit
            cipher = AES.new(aes_key, AES.MODE_GCM)
            ct, tag = cipher.encrypt_and_digest(data)
            # store: nonce + tag + ct
            packed_cipher = cipher.nonce + tag + ct
            packed = _pack_with_metadata(original_name, packed_cipher, b"")
            key_str = base64.b64encode(aes_key).decode("utf-8")

        # Fernet
        elif method == "Fernet":
            key = Fernet.generate_key()
            f = Fernet(key)
            ct = f.encrypt(data)
            packed = _pack_with_metadata(original_name, ct, b"")
            key_str = key.decode("utf-8")

        # RSA-hybrid: RSA encrypts AES key, AES-GCM encrypts file
        elif method == "RSA":
            rsa_key = RSA.generate(2048)
            private_key = rsa_key.export_key()  # bytes
            public_key = rsa_key.publickey()
            aes_key = get_random_bytes(32)
            cipher_aes = AES.new(aes_key, AES.MODE_GCM)
            ct, tag = cipher_aes.encrypt_and_digest(data)
            packed_cipher = cipher_aes.nonce + tag + ct
            rsa_cipher = PKCS1_OAEP.new(public_key)
            encrypted_aes_key = rsa_cipher.encrypt(aes_key)
            packed = _pack_with_metadata(original_name, packed_cipher, encrypted_aes_key)
            # NOTE: returning private key for local dev convenience (NOT for production)
            key_str = base64.b64encode(private_key).decode("utf-8")

        else:
            return jsonify({"error": "Unsupported method"}), 400

        # Save encrypted file
        out_name = f"{os.path.splitext(original_name)[0]}_encrypted.bin"
        out_path = os.path.join(ENCRYPTED_FOLDER, out_name)
        with open(out_path, "wb") as of:
            of.write(packed)

        # Build response JSON and set header
        resp = make_response(jsonify({"filename": out_name, "key": key_str}))
        resp.headers["X-Encryption-Key"] = key_str
        resp.headers["Access-Control-Expose-Headers"] = "X-Encryption-Key"
        return resp

    except Exception:
        traceback.print_exc()
        return jsonify({"error": "Encryption failed on server"}), 500


@app.route("/download/<path:filename>", methods=["GET"])
def download_encrypted(filename):
    path = os.path.join(ENCRYPTED_FOLDER, filename)
    if not os.path.isfile(path):
        return jsonify({"error": "File not found"}), 404
    return send_file(path, as_attachment=True)


@app.route("/decrypt", methods=["POST"])
def decrypt_endpoint():
    try:
        file = request.files.get("file")
        method = request.form.get("method", "AES")
        key_str = request.form.get("key")

        if not file or not key_str:
            return jsonify({"error": "File and key are required"}), 400

        packed = file.read()

        orig_filename, extra, ciphertext = _unpack_with_metadata(packed)

        if method == "AES":
            aes_key = base64.b64decode(key_str)
            # ciphertext: nonce(16) + tag(16) + ct
            nonce = ciphertext[:16]
            tag = ciphertext[16:32]
            ct = ciphertext[32:]
            cipher = AES.new(aes_key, AES.MODE_GCM, nonce=nonce)
            plaintext = cipher.decrypt_and_verify(ct, tag)

        elif method == "Fernet":
            f = Fernet(key_str.encode())
            plaintext = f.decrypt(ciphertext)

        elif method == "RSA":
            # extra should contain RSA-encrypted AES key
            if not extra:
                return jsonify({"error": "Missing encrypted AES key inside file for RSA."}), 400
            priv_key_bytes = base64.b64decode(key_str)
            private = RSA.import_key(priv_key_bytes)
            rsa_cipher = PKCS1_OAEP.new(private)
            aes_key = rsa_cipher.decrypt(extra)
            nonce = ciphertext[:16]
            tag = ciphertext[16:32]
            ct = ciphertext[32:]
            cipher = AES.new(aes_key, AES.MODE_GCM, nonce=nonce)
            plaintext = cipher.decrypt_and_verify(ct, tag)

        else:
            return jsonify({"error": "Unsupported method"}), 400

        # Save decrypted file to disk so send_file can serve with filename
        dec_path = os.path.join(DECRYPTED_FOLDER, orig_filename)
        with open(dec_path, "wb") as df:
            df.write(plaintext)

        # try to guess mime type
        mtype, _ = mimetypes.guess_type(orig_filename)
        mtype = mtype or "application/octet-stream"

        try:
            return send_file(dec_path, as_attachment=True, download_name=orig_filename, mimetype=mtype)
        except TypeError:
            # older Flask: use Response with Content-Disposition
            headers = {"Content-Disposition": f'attachment; filename="{orig_filename}"'}
            return Response(plaintext, mimetype=mtype, headers=headers)

    except Exception:
        traceback.print_exc()
        return jsonify({"error": "Decryption failed on server"}), 500


if __name__ == "__main__":
    app.run(debug=True)
