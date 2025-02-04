import sys
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric.utils import encode_dss_signature, decode_dss_signature
from cryptography.hazmat.primitives import serialization

# Generate ECC private and public keys for a vehicle (actor in VANET)
def generate_keys():
    private_key = ec.generate_private_key(ec.SECP256R1(), default_backend())
    public_key = private_key.public_key()
    return private_key, public_key

# Serialize the public key for transmission
def serialize_public_key(public_key):
    return public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )

# Function to sign data (for authentication and integrity)
def sign_data(private_key, data):
    signature = private_key.sign(data, ec.ECDSA(hashes.SHA256()))
    r, s = decode_dss_signature(signature)
    return r, s

# Verify the signature (Zero Trust principle: Always verify)
def verify_signature(public_key, data, signature):
    try:
        r, s = signature
        der_signature = encode_dss_signature(r, s)
        public_key.verify(der_signature, data, ec.ECDSA(hashes.SHA256()))
        print("Signature is valid.")
        return True
    except Exception as e:
        print(f"Signature verification failed: {e}")
        return False

# Example of a Zero Trust Check in VANET Cloud
def zero_trust_access_request(vehicle_id, public_key, data, signature):
    print(f"Vehicle {vehicle_id} is requesting access...")
    # Enforcing Zero Trust - Always authenticate and verify
    if verify_signature(public_key, data, signature):
        print("Access granted based on valid authentication.")
    else:
        print("Access denied due to authentication failure.")

# Example of the main operation
if __name__ == "__main__":
    # Generating keys for a vehicle in the VANET
    private_key, public_key = generate_keys()

    # Data that needs to be signed (e.g., a message or a request)
    data = b"Requesting access to VANET cloud services"

    # Signing the data using the vehicle's private key
    r, s = sign_data(private_key, data)

    # Zero Trust enforced access request in VANET
    zero_trust_access_request(vehicle_id="Vehicle_123", public_key=public_key, data=data, signature=(r, s))
