# main.py

from flask import Flask, request, jsonify
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.backends import default_backend
from datetime import datetime, timedelta
import jwt
import sqlite3

app = Flask(__name__)

# Connect to SQLite database
conn = sqlite3.connect('totally_not_my_privateKeys.db')
c = conn.cursor()

# Create table if not exists
c.execute('''CREATE TABLE IF NOT EXISTS keys(
                kid INTEGER PRIMARY KEY AUTOINCREMENT,
                key TEXT NOT NULL,
                exp INTEGER NOT NULL
             )''')

# Generate RSA key pair
private_key = rsa.generate_private_key(
    public_exponent=65537,
    key_size=2048,
    backend=default_backend()
)

# Encode private key to PEM format
private_pem = private_key.private_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PrivateFormat.PKCS8,
    encryption_algorithm=serialization.NoEncryption()
)

# Key ID and expiry timestamp
kid = "key1"
expiry = datetime.utcnow() + timedelta(days=30)

# Save private key to the database
key_data = (private_pem.decode(), expiry.timestamp())
c.execute('INSERT INTO keys (key, exp) VALUES (?, ?)', key_data)
conn.commit()

@app.route('/')
def index():
    return "Welcome to the JWKS server!"

@app.route('/jwks', methods=['GET'])
def jwks():
    jwks_keys = []
    # Retrieve valid keys from the database
    for row in c.execute('SELECT * FROM keys WHERE exp > ?', (datetime.utcnow().timestamp(),)):
        jwks_keys.append({
            "kid": row[0],
            "kty": "RSA",
            "alg": "RS256",
            "use": "sig",
            "n": private_key.public_key().public_numbers().n,
            "e": private_key.public_key().public_numbers().e
        })
    return jsonify(keys={"keys": jwks_keys})

@app.route('/auth', methods=['POST'])
def auth():
    expired = request.args.get('expired')
    if expired:
        c.execute('SELECT * FROM keys WHERE exp <= ?', (datetime.utcnow().timestamp(),))
    else:
        c.execute('SELECT * FROM keys WHERE exp > ?', (datetime.utcnow().timestamp(),))

    key_row = c.fetchone()
    key = serialization.load_pem_private_key(key_row[1].encode(), password=None, backend=default_backend())

    # Convert the kid to a string if it's not already
    kid = str(key_row[0])

    # Sign the JWT token using the RSA private key
    token = jwt.encode({'some': 'payload'}, key, algorithm='RS256', headers={'kid': kid})
    return jsonify({'access_token': token})


if __name__ == '__main__':
    app.run(port=8080)
