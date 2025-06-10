from cryptography.hazmat.primitives.asymmetric import dh # type: ignore
from cryptography.hazmat.primitives import serialization # type: ignore
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC # type: ignore
from cryptography.hazmat.primitives import hashes # type: ignore

def generate_client_key_pair(parameters):
    private_key = parameters.generate_private_key()
    public_key = private_key.public_key()
    return private_key, public_key

def derive_shared_secret(private_key, server_public_key):
    shared_key = private_key.exchange(server_public_key)
    return shared_key

def main():
    # Load server's public key
    with open("server_public_key.pem", "rb") as f:
        server_public_key = serialization.load_pem_public_key(f.read())

    parameters = server_public_key.parameters()
    private_key, public_key = generate_client_key_pair(parameters)

    shared_secret = derive_shared_secret(private_key, server_public_key)

    print("Shared Secret:", shared_secret.hex())

if __name__ == "__main__":
    main()
