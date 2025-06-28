import os
import time
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.exceptions import InvalidTag

# --- Part 1: Secure End-to-End Encrypted Messaging ---

# Represents a user in the secure messaging system to generate keys, perform key exchange, and encrypt/decrypt messages.
class User:
    def __init__(self, name):
        self.name = name
        self.private_key = None
        self.public_key = None
        self.shared_secret = None
        self.encryption_key = None

    # Generates an ECDHE private and public key pair for the user. Uses the secp384r1 curve for strong security.
    def generate_keys(self):
        print(f"[{self.name}] Generating ECDHE key pair...")
        self.private_key = ec.generate_private_key(
            ec.SECP384R1(), default_backend()
        )
        self.public_key = self.private_key.public_key()
        print(f"[{self.name}] Key pair generated.")
        print(f"[{self.name}] Private Key (first 8 bytes): {self.private_key.private_numbers().private_value.to_bytes(48, 'big')[:8].hex()}...")
        print(f"[{self.name}] Public Key (first 8 bytes): {self.public_key.public_numbers().x.to_bytes(48, 'big')[:8].hex()}...")


    # Performs the ECDHE key exchange to get a shared secret to get the final encryption key using HKDF with SHA-256.
    def perform_key_exchange(self, other_public_key):
        print(f"[{self.name}] Performing key exchange with partner's public key...")
        # Get the shared secret using the user's private key and the other user's public key
        self.shared_secret = self.private_key.exchange(ec.ECDH(), other_public_key)
        print(f"[{self.name}] Shared secret derived (first 8 bytes): {self.shared_secret[:8].hex()}...")

        # Get a strong encryption key from the shared secret using HKDF
        self.encryption_key = HKDF(
            algorithm=hashes.SHA256(),
            length=32,  # AES-256 requires a 32-byte (256-bit) key
            salt=None,  
            info=b'handshake data',
            backend=default_backend()
        ).derive(self.shared_secret)
        print(f"[{self.name}] Encryption key derived from shared secret (first 8 bytes): {self.encryption_key[:8].hex()}...")

    # Encrypts a message using AES-256 GCM that provides both confidentiality and authenticated encryption (integrity and authenticity).
    def encrypt_message(self, message):
        if not self.encryption_key:
            raise ValueError("Encryption key not established. Perform key exchange first.")

        # AES GCM requires a unique nonce (Initialization Vector) for each encryption.
        nonce = os.urandom(12) # GCM recommends a 96-bit (12-byte) nonce

        # Create an AES cipher object with GCM mode
        cipher = Cipher(algorithms.AES(self.encryption_key), modes.GCM(nonce), backend=default_backend())
        encryptor = cipher.encryptor()

        # Encrypt the plaintext. The 'update' method processes the data.
        ciphertext = encryptor.update(message.encode('utf-8')) + encryptor.finalize()

        # The GCM tag provides integrity and authenticity.
        tag = encryptor.tag

        print(f"[{self.name}] Message encrypted.")
        print(f"[{self.name}] Nonce: {nonce.hex()}")
        print(f"[{self.name}] Ciphertext (first 16 bytes): {ciphertext[:16].hex()}...")
        print(f"[{self.name}] Tag: {tag.hex()}")
        return nonce, ciphertext, tag

    # Decrypts a message using AES-256 GCM. It verifies the integrity of the message using the provided tag.
    def decrypt_message(self, nonce, ciphertext, tag):
        if not self.encryption_key:
            raise ValueError("Encryption key not established. Perform key exchange first.")

        print(f"[{self.name}] Starting decryption process...")
        print(f"[{self.name}] Using Encryption Key (first 8 bytes): {self.encryption_key[:8].hex()}...")
        print(f"[{self.name}] Using Nonce: {nonce.hex()}")
        print(f"[{self.name}] Using Ciphertext (first 16 bytes): {ciphertext[:16].hex()}...")
        print(f"[{self.name}] Using Tag: {tag.hex()}")

        # Create an AES cipher object with GCM mode and the provided nonce and tag
        cipher = Cipher(algorithms.AES(self.encryption_key), modes.GCM(nonce, tag), backend=default_backend())
        decryptor = cipher.decryptor()

        try:
            print(f"[{self.name}] Attempting to decrypt and verify integrity...")
            # Decrypt the ciphertext. The 'update' method processes the data.
            # If the tag is invalid, an InvalidTag exception will be raised during finalize().
            plaintext = decryptor.update(ciphertext) + decryptor.finalize()
            print(f"[{self.name}] Message decrypted successfully. Integrity verified.")
            return plaintext.decode('utf-8')
        except InvalidTag:
            print(f"[{self.name}] Decryption failed: Message authentication code (tag) is invalid. "
                  "The message may have been tampered with or the key/nonce is incorrect.")
            return None


# Demonstrates the end-to-end encrypted messaging flow between Alice and Bob.
def run_messaging_demo():
    print("\n--- Secure End-to-End Encrypted Messaging Demo ---")

    # 1. Initialize Users
    alice = User("Alice")
    bob = User("Bob")

    # 2. Key Generation
    alice.generate_keys()
    bob.generate_keys()

    # 3. Key Exchange (Public keys are exchanged over an insecure channel)
    # Alice sends her public key to Bob, and Bob sends his public key to Alice.
    # Each then derives the shared secret independently.
    alice.perform_key_exchange(bob.public_key)
    bob.perform_key_exchange(alice.public_key)

    # Verify that both shared secrets and derived encryption keys are identical
    if alice.shared_secret == bob.shared_secret:
        print("\nShared secrets match! Secure channel established.")
    else:
        print("\nError: Shared secrets do NOT match!")
        return

    if alice.encryption_key == bob.encryption_key:
        print("Derived encryption keys match!")
    else:
        print("Error: Derived encryption keys do NOT match!")
        return

    # 4. Interactive Message Exchange
    while True:
        # Alice sends a message
        message_from_alice = input("\n[From Alice] Enter message: ")

        print(f"\n--- Alice sending message to Bob ---")
        nonce_alice, ciphertext_alice, tag_alice = alice.encrypt_message(message_from_alice)

        print(f"\n--- Bob receiving and decrypting message from Alice ---")
        decrypted_message_by_bob = bob.decrypt_message(nonce_alice, ciphertext_alice, tag_alice)

        if decrypted_message_by_bob is not None:
            print(f"[{bob.name}] Decrypted message: '{decrypted_message_by_bob}'")
        else:
            print(f"[{bob.name}] Could not decrypt message.")


        # Bob sends a message
        message_from_bob = input("\n[From Bob] Enter message: ")
        if message_from_bob.lower() == 'e':
            break

        print(f"\n--- Bob sending message to Alice ---")
        nonce_bob, ciphertext_bob, tag_bob = bob.encrypt_message(message_from_bob)

        print(f"\n--- Alice receiving and decrypting message from Bob ---")
        decrypted_message_by_alice = alice.decrypt_message(nonce_bob, ciphertext_bob, tag_bob)
        if decrypted_message_by_alice is not None:
            print(f"[{alice.name}] Decrypted message: '{decrypted_message_by_alice}'")
        else:
            print(f"[{alice.name}] Could not decrypt message.")
        
        # Ask if user want to run performance test
        while True:
            performance_test_input = ""
            
            performance_test_input = input("\nRun performance test? [y/n]: ").lower()
            if performance_test_input == 'y':
                exit_loop = True
                break
            elif performance_test_input == 'n':
                exit_loop = False
                break
            else:
                print("Invalid input. Please enter 'y' or 'n'.")

        if exit_loop:
            break


# --- Part 2: Performance Test ---

def run_performance_test(data_size_mb):
    """
    Tests the encryption and decryption performance for a large amount of data.
    """
    
    print(f"\n--- Performance Test: Encrypting/Decrypting {data_size_mb} MB of data ---")

    # Generate dummy data for testing
    dummy_data = os.urandom(data_size_mb * 1024 * 1024) # 100 MB of random bytes

    # Initialize a dummy user for performance testing
    test_user = User("TestUser")
    test_user.generate_keys()
    # For performance test, we just need an encryption key,
    # so we'll simulate key exchange to get one.
    # In a real scenario, this would be a full ECDHE.
    dummy_partner_key = ec.generate_private_key(ec.SECP384R1(), default_backend()).public_key()
    test_user.perform_key_exchange(dummy_partner_key)

    # Encryption Test
    start_time = time.time()
    nonce, ciphertext, tag = test_user.encrypt_message(dummy_data.decode('latin-1')) # Decode as latin-1 for raw bytes
    encryption_time = time.time() - start_time
    print(f"Encryption took: {encryption_time:.4f} seconds")

    # Decryption Test
    start_time = time.time()
    decrypted_data = test_user.decrypt_message(nonce, ciphertext, tag)
    decryption_time = time.time() - start_time
    print(f"Decryption took: {decryption_time:.4f} seconds")

    # Calculate Throughput
    data_size_bytes = len(dummy_data)
    encryption_throughput_mbps = (data_size_bytes / (1024 * 1024)) / encryption_time
    decryption_throughput_mbps = (data_size_bytes / (1024 * 1024)) / decryption_time

    return {
        "encryption_time": encryption_time,
        "decryption_time": decryption_time,
        "encryption_throughput_mbps": encryption_throughput_mbps,
        "decryption_throughput_mbps": decryption_throughput_mbps,
        "data_size_mb": data_size_mb
    }

# --- Main Execution ---
if __name__ == "__main__":
    # Run the interactive messaging demo
    run_messaging_demo()

    # Run the performance test
    performance_results = run_performance_test(data_size_mb=100)

    print("\n--- Assessment of Cryptographic Solution Appropriateness ---")
    print("\nKey Parameters from Performance Test:")
    print("| Parameter                  | Value                     |")
    print("|----------------------------|---------------------------|")
    print(f"| Data Size Tested           | {performance_results['data_size_mb']} MB                 ")
    print(f"| Encryption Latency         | {performance_results['encryption_time']:.4f} seconds     ")
    print(f"| Decryption Latency         | {performance_results['decryption_time']:.4f} seconds     ")
    print(f"| Encryption Throughput      | {performance_results['encryption_throughput_mbps']:.2f} MB/s      ")
    print(f"| Decryption Throughput      | {performance_results['decryption_throughput_mbps']:.2f} MB/s      ")
    print("|----------------------------|---------------------------|")