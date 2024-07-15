from flask import Flask, render_template, request, jsonify
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes
from cryptography.exceptions import InvalidSignature

app = Flask(__name__)

# Generate RSA keys
def generate_keys():
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048
    )
    public_key = private_key.public_key()
    return private_key, public_key

private_key, public_key = generate_keys()

# Sign message
def sign_message(message, private_key):
    signature = private_key.sign(
        message,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )
    return signature

# Verify signature
def verify_signature(message, signature, public_key):
    try:
        public_key.verify(
            signature,
            message,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        return True
    except InvalidSignature:
        return False

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/generate_certificate', methods=['POST'])
def generate_certificate():
    data = request.json
    message = data.get('message')
    signature = sign_message(message.encode(), private_key)
    return jsonify({'message': message, 'signature': signature.hex()})

@app.route('/verify_certificate', methods=['POST'])
def verify_certificate():
    data = request.json
    message = data.get('message')
    signature = bytes.fromhex(data.get('signature'))
    valid = verify_signature(message.encode(), signature, public_key)
    return jsonify({'valid': valid})

if __name__ == '__main__':
    app.run(debug=True)