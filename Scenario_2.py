import os
import sys
import time
from datetime import datetime
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, ec, padding
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.exceptions import InvalidSignature, InvalidTag

# --- Helper Class for AES-256 GCM Symmetric Encryption ---
class AES_256_GCM_Cipher:
    def __init__(self):
        pass

    def encrypt(self, data: bytes, encryption_key: bytes):
        """Encrypts data using AES-256 GCM."""
        nonce = os.urandom(12)  # GCM recommends a 96-bit nonce
        cipher = Cipher(algorithms.AES(encryption_key), modes.GCM(nonce), backend=default_backend())
        encryptor = cipher.encryptor()
        ciphertext = encryptor.update(data) + encryptor.finalize()
        tag = encryptor.tag
        return nonce, ciphertext, tag

    def decrypt(self, nonce: bytes, ciphertext: bytes, tag: bytes, encryption_key: bytes):
        """Decrypts data using AES-256 GCM and verifies integrity."""
        cipher = Cipher(algorithms.AES(encryption_key), modes.GCM(nonce, tag), backend=default_backend())
        decryptor = cipher.decryptor()
        try:
            plaintext = decryptor.update(ciphertext) + decryptor.finalize()
            return plaintext
        except InvalidTag:
            raise ValueError("Decryption failed: Message authentication code (tag) is invalid or data tampered.")

# --- Key Generation and Management ---
class KeyManager:
    def __init__(self):
        self.rsa_private_keys = {}
        self.rsa_public_keys = {}
        self.ecdsa_private_keys = {}
        self.ecdsa_public_keys = {}

    def generate_rsa_key_pair(self, user_id: str):
        """Generates an RSA public/private key pair for a user."""
        print(f"[KeyManager] Generating RSA key pair for {user_id}...")
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
            backend=default_backend()
        )
        public_key = private_key.public_key()
        self.rsa_private_keys[user_id] = private_key
        self.rsa_public_keys[user_id] = public_key
        print(f"[KeyManager] RSA key pair generated for {user_id}.")
        print(f"  Public Key (first 8 bytes of modulus): {public_key.public_numbers().n.to_bytes(256, 'big')[:8].hex()}...")
        # Private key material is sensitive and not printed in full

    def generate_ecdsa_key_pair(self, user_id: str):
        """Generates an ECDSA public/private key pair for a user."""
        print(f"[KeyManager] Generating ECDSA key pair for {user_id}...")
        private_key = ec.generate_private_key(
            ec.SECP384R1(), # SECP384R1 is a strong elliptic curve
            default_backend()
        )
        public_key = private_key.public_key()
        self.ecdsa_private_keys[user_id] = private_key
        self.ecdsa_public_keys[user_id] = public_key
        print(f"[KeyManager] ECDSA key pair generated for {user_id}.")
        print(f"  Public Key (first 8 bytes of X-coordinate): {public_key.public_numbers().x.to_bytes(48, 'big')[:8].hex()}...")
        # Private key material is sensitive and not printed in full

    def get_rsa_public_key(self, user_id: str):
        return self.rsa_public_keys.get(user_id)

    def get_rsa_private_key(self, user_id: str):
        return self.rsa_private_keys.get(user_id)

    def get_ecdsa_public_key(self, user_id: str):
        return self.ecdsa_public_keys.get(user_id)

    def get_ecdsa_private_key(self, user_id: str):
        return self.ecdsa_private_keys.get(user_id)

# --- Document Archiving Class ---
class SecureDocumentArchiver:
    def __init__(self, key_manager: KeyManager):
        self.key_manager = key_manager
        self.aes_cipher = AES_256_GCM_Cipher()
        self.archived_documents = {} # Stores archived document data

    def archive_document(self, document_id: str, plaintext_data: bytes, archiver_id: str, recipient_ids: list):
        """
        Encrypts a document, signs its hash, and encrypts the symmetric key for multiple recipients.
        """
        print(f"\n--- Archiving Document '{document_id}' by '{archiver_id}' ---")

        # 1. Hash the original document (SHA-512)
        print(f"  [Step 1] Hashing original document with SHA-512...")
        document_hash = hashes.Hash(hashes.SHA512(), backend=default_backend())
        document_hash.update(plaintext_data)
        final_document_hash = document_hash.finalize()
        print(f"  Original Document SHA-512 Hash: {final_document_hash.hex()}")

        # 2. Generate a random symmetric key for the document (AES-256)
        print(f"  [Step 2] Generating a new AES-256 symmetric key for document encryption...")
        document_aes_key = os.urandom(32) # 256-bit key
        print(f"  Document AES Key (first 8 bytes): {document_aes_key[:8].hex()}...")

        # 3. Encrypt the document data with AES-256 GCM
        print(f"  [Step 3] Encrypting document content with AES-256 GCM...")
        nonce, ciphertext, tag = self.aes_cipher.encrypt(plaintext_data, document_aes_key)
        print(f"  AES Nonce: {nonce.hex()}")
        print(f"  AES Ciphertext (first 16 bytes): {ciphertext[:16].hex()}...")
        print(f"  AES Tag: {tag.hex()}")

        # 4. Digital Signature (ECDSA) of the document hash
        print(f"  [Step 4] Signing the document hash with ECDSA by '{archiver_id}'...")
        archiver_ecdsa_private_key = self.key_manager.get_ecdsa_private_key(archiver_id)
        if not archiver_ecdsa_private_key:
            raise ValueError(f"Archiver '{archiver_id}' ECDSA private key not found.")

        signature = archiver_ecdsa_private_key.sign(
            final_document_hash,
            ec.ECDSA(hashes.SHA512()) # Use SHA-512 for signing the hash
        )
        print(f"  ECDSA Signature (first 16 bytes): {signature[:16].hex()}...")

        # 5. Encrypt the symmetric document key for each recipient with RSA
        print(f"  [Step 5] Encrypting the document's AES key for each recipient with RSA...")
        encrypted_aes_keys = {}
        for recipient_id in recipient_ids:
            recipient_rsa_public_key = self.key_manager.get_rsa_public_key(recipient_id)
            if not recipient_rsa_public_key:
                print(f"  Warning: Recipient '{recipient_id}' RSA public key not found. Skipping.")
                continue

            encrypted_key = recipient_rsa_public_key.encrypt(
                document_aes_key,
                padding.OAEP(
                    mgf=padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None
                )
            )
            encrypted_aes_keys[recipient_id] = encrypted_key
            print(f"  AES Key encrypted for '{recipient_id}' (first 8 bytes): {encrypted_key[:8].hex()}...")

        # Store the archived document components
        self.archived_documents[document_id] = {
            "archiver_id": archiver_id,
            "timestamp": datetime.now().isoformat(),
            "original_hash_sha512": final_document_hash,
            "encrypted_content": ciphertext,
            "nonce": nonce,
            "tag": tag,
            "ecdsa_signature": signature,
            "encrypted_aes_keys": encrypted_aes_keys, # RSA-encrypted AES key for each recipient
            "recipients": recipient_ids
        }
        print(f"\nDocument '{document_id}' successfully archived.")

    def retrieve_document(self, document_id: str, user_id: str):
        """
        Retrieves and decrypts an archived document, verifying its integrity and authenticity.
        """
        print(f"\n--- Attempting to retrieve Document '{document_id}' by '{user_id}' ---")
        archived_data = self.archived_documents.get(document_id)

        if not archived_data:
            print(f"  Error: Document '{document_id}' not found.")
            return None

        if user_id not in archived_data["recipients"]:
            print(f"  Error: User '{user_id}' is not an authorized recipient for document '{document_id}'.")
            return None

        # 1. Decrypt the symmetric document key with user's RSA private key
        print(f"  [Step 1] Decrypting document's AES key with '{user_id}'s RSA private key...")
        user_rsa_private_key = self.key_manager.get_rsa_private_key(user_id)
        if not user_rsa_private_key:
            print(f"  Error: User '{user_id}' RSA private key not found for decryption.")
            return None

        encrypted_aes_key_for_user = archived_data["encrypted_aes_keys"].get(user_id)
        if not encrypted_aes_key_for_user:
            print(f"  Error: No encrypted AES key found for user '{user_id}' in document '{document_id}'.")
            return None

        try:
            document_aes_key = user_rsa_private_key.decrypt(
                encrypted_aes_key_for_user,
                padding.OAEP(
                    mgf=padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None
                )
            )
            print(f"  Document AES Key decrypted (first 8 bytes): {document_aes_key[:8].hex()}...")
        except Exception as e:
            print(f"  Error decrypting AES key for '{user_id}': {e}")
            return None

        # 2. Decrypt the document content with AES-256 GCM
        print(f"  [Step 2] Decrypting document content with AES-256 GCM...")
        try:
            plaintext_data = self.aes_cipher.decrypt(
                archived_data["nonce"],
                archived_data["encrypted_content"],
                archived_data["tag"],
                document_aes_key
            )
            print(f"  Document content decrypted.")
        except ValueError as e:
            print(f"  Error decrypting document content: {e}")
            return None

        # 3. Verify the digital signature (ECDSA)
        print(f"  [Step 3] Verifying digital signature...")
        archiver_ecdsa_public_key = self.key_manager.get_ecdsa_public_key(archived_data["archiver_id"])
        if not archiver_ecdsa_public_key:
            print(f"  Error: Archiver '{archived_data['archiver_id']}' ECDSA public key not found for signature verification.")
            return None

        try:
            # Re-hash the decrypted plaintext to verify against the stored hash and signature
            rehashed_data = hashes.Hash(hashes.SHA512(), backend=default_backend())
            rehashed_data.update(plaintext_data)
            recalculated_hash = rehashed_data.finalize()

            archiver_ecdsa_public_key.verify(
                archived_data["ecdsa_signature"],
                recalculated_hash, # Verify against the hash of the *decrypted* content
                ec.ECDSA(hashes.SHA512())
            )
            print(f"  Digital Signature Verified: Authenticity confirmed.")
        except InvalidSignature:
            print(f"  Digital Signature Verification Failed: Document authenticity or integrity compromised!")
            return None
        except Exception as e:
            print(f"  Error during signature verification: {e}")
            return None

        # 4. Verify document integrity by comparing hashes
        print(f"  [Step 4] Comparing original and recalculated SHA-512 hashes...")
        recalculated_hash_for_integrity = hashes.Hash(hashes.SHA512(), backend=default_backend())
        recalculated_hash_for_integrity.update(plaintext_data)
        final_recalculated_hash_for_integrity = recalculated_hash_for_integrity.finalize()

        if final_recalculated_hash_for_integrity == archived_data["original_hash_sha512"]:
            print(f"  Document Integrity Verified: Hashes match!")
            print(f"  Original SHA-512 Hash: {archived_data['original_hash_sha512'].hex()}")
            print(f"  Recalculated SHA-512 Hash: {final_recalculated_hash_for_integrity.hex()}")
        else:
            print(f"  Document Integrity Compromised: Hashes DO NOT MATCH!")
            print(f"  Original SHA-512 Hash: {archived_data['original_hash_sha512'].hex()}")
            print(f"  Recalculated SHA-512 Hash: {final_recalculated_hash_for_integrity.hex()}")
            return None

        print(f"\nDocument '{document_id}' retrieved and verified successfully by '{user_id}'.")
        return plaintext_data.decode('utf-8')

# --- Performance Testing Function ---
def run_performance_test(archiver: SecureDocumentArchiver, key_manager: KeyManager, data_size_mb):
    """
    Tests the performance of archiving and retrieving a large document.
    """
    print(f"\n--- Performance Test: Archiving/Retrieving {data_size_mb} MB of data ---")

    # Generate dummy data for testing
    dummy_data = os.urandom(data_size_mb * 1024 * 1024) # 10 MB of random bytes

    # Define test users
    archiver_id = "TestArchiver"
    recipient_ids = ["TestRecipient1", "TestRecipient2"]

    # Ensure keys exist for test users
    key_manager.generate_rsa_key_pair(archiver_id)
    key_manager.generate_ecdsa_key_pair(archiver_id)
    for rid in recipient_ids:
        key_manager.generate_rsa_key_pair(rid)

    # --- Archiving Performance ---
    archive_start_time = time.time()

    # Hash
    hash_start = time.time()
    document_hash = hashes.Hash(hashes.SHA512(), backend=default_backend())
    document_hash.update(dummy_data)
    final_document_hash = document_hash.finalize()
    hash_time = time.time() - hash_start

    # Symmetric Key Generation
    aes_key_gen_start = time.time()
    document_aes_key = os.urandom(32)
    aes_key_gen_time = time.time() - aes_key_gen_start

    # Document Encryption (AES-256 GCM)
    aes_encrypt_start = time.time()
    nonce, ciphertext, tag = archiver.aes_cipher.encrypt(dummy_data, document_aes_key)
    aes_encrypt_time = time.time() - aes_encrypt_start

    # Digital Signature (ECDSA)
    ecdsa_sign_start = time.time()
    archiver_ecdsa_private_key = key_manager.get_ecdsa_private_key(archiver_id)
    signature = archiver_ecdsa_private_key.sign(
        final_document_hash,
        ec.ECDSA(hashes.SHA512())
    )
    ecdsa_sign_time = time.time() - ecdsa_sign_start

    # RSA Encryption of Symmetric Keys
    rsa_encrypt_keys_start = time.time()
    encrypted_aes_keys = {}
    for recipient_id in recipient_ids:
        recipient_rsa_public_key = key_manager.get_rsa_public_key(recipient_id)
        encrypted_key = recipient_rsa_public_key.encrypt(
            document_aes_key,
            padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None)
        )
        encrypted_aes_keys[recipient_id] = encrypted_key
    rsa_encrypt_keys_time = time.time() - rsa_encrypt_keys_start

    archive_end_time = time.time()
    total_archiving_time = archive_end_time - archive_start_time

    print(f"  Archiving took: {total_archiving_time:.4f} seconds")

    # --- Retrieval Performance ---
    retrieve_start_time = time.time()
    retriever_id = recipient_ids[0] # Test with the first recipient

    # RSA Decryption of Symmetric Key
    rsa_decrypt_key_start = time.time()
    user_rsa_private_key = key_manager.get_rsa_private_key(retriever_id)
    decrypted_aes_key = user_rsa_private_key.decrypt(
        encrypted_aes_keys[retriever_id],
        padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None)
    )
    rsa_decrypt_key_time = time.time() - rsa_decrypt_key_start

    # Document Decryption (AES-256 GCM)
    aes_decrypt_start = time.time()
    decrypted_data = archiver.aes_cipher.decrypt(nonce, ciphertext, tag, decrypted_aes_key)
    aes_decrypt_time = time.time() - aes_decrypt_start

    # Re-hash for verification
    rehash_start = time.time()
    rehashed_data = hashes.Hash(hashes.SHA512(), backend=default_backend())
    rehashed_data.update(decrypted_data)
    recalculated_hash = rehashed_data.finalize()
    rehash_time = time.time() - rehash_start

    # ECDSA Signature Verification
    ecdsa_verify_start = time.time()
    archiver_ecdsa_public_key = key_manager.get_ecdsa_public_key(archiver_id)
    try:
        archiver_ecdsa_public_key.verify(
            signature,
            recalculated_hash,
            ec.ECDSA(hashes.SHA512())
        )
        ecdsa_verify_success = True
    except InvalidSignature:
        ecdsa_verify_success = False
    ecdsa_verify_time = time.time() - ecdsa_verify_start

    total_retrieval_time = time.time() - retrieve_start_time
    print(f"  Retrieval took: {total_retrieval_time:.4f} seconds")

    # Calculate Throughput
    data_size_bytes = len(dummy_data)
    encryption_throughput_mbps = (data_size_bytes / (1024 * 1024)) / aes_encrypt_time
    decryption_throughput_mbps = (data_size_bytes / (1024 * 1024)) / aes_decrypt_time

    return {
        "data_size_mb": data_size_mb,
        "total_archiving_time": total_archiving_time,
        "total_retrieval_time": total_retrieval_time,
        "hash_time": hash_time,
        "aes_key_gen_time": aes_key_gen_time,
        "aes_encrypt_time": aes_encrypt_time,
        "ecdsa_sign_time": ecdsa_sign_time,
        "rsa_encrypt_keys_time": rsa_encrypt_keys_time,
        "rsa_decrypt_key_time": rsa_decrypt_key_time,
        "aes_decrypt_time": aes_decrypt_time,
        "rehash_time": rehash_time,
        "ecdsa_verify_time": ecdsa_verify_time,
        "encryption_throughput_mbps": encryption_throughput_mbps,
        "decryption_throughput_mbps": decryption_throughput_mbps,
        "ecdsa_verify_success": ecdsa_verify_success
    }

# --- Main Execution ---
if __name__ == "__main__":
    key_manager = KeyManager()
    archiver_system = SecureDocumentArchiver(key_manager)

    # --- Setup Users (Archiver and Viewers) ---
    print("--- Setting up Users and Generating Keys ---")
    archiver_name = "Alice"
    viewer_names = ["Alice", "Bob", "Charlie"]

    key_manager.generate_rsa_key_pair(archiver_name)
    key_manager.generate_ecdsa_key_pair(archiver_name) # Archiver needs ECDSA for signing

    for viewer in viewer_names:
        key_manager.generate_rsa_key_pair(viewer)


    # --- Document Archiving Demo ---
    print("\n--- Document Archiving Demo ---")
    doc_id = input("Enter a Document ID (e.g., 'Secret_1'): ")

    doc_content_bytes = b""
    file_path_input = input("Enter a file path to upload (e.g., 'secret.txt') OR type 'text' to enter content directly OR type 'dummy' for a small test string: ").lower()

    if file_path_input == 'text':
        doc_content_str = input("Enter the document content: ")
        doc_content_bytes = doc_content_str.encode('utf-8')
    elif file_path_input == 'dummy':
        doc_content_str = "This is a small dummy document for demonstration purposes. It contains some sensitive information that needs to be securely archived."
        print(f"Using dummy content: '{doc_content_str}'")
        doc_content_bytes = doc_content_str.encode('utf-8')
    else:
        # Attempt to read from file path
        try:
            with open(file_path_input, 'rb') as f:
                doc_content_bytes = f.read()
            print(f"Attempted to read content from '{file_path_input}'.")
        except FileNotFoundError:
            print(f"Warning: File '{file_path_input}' not found. Falling back to dummy content.")
            doc_content_str = "This is a small dummy document for demonstration purposes. File not found fallback."
            doc_content_bytes = doc_content_str.encode('utf-8')
        except Exception as e:
            print(f"Warning: Could not read file '{file_path_input}' ({e}). Falling back to dummy content.")
            doc_content_str = "This is a small dummy document for demonstration purposes. File read error fallback."
            doc_content_bytes = doc_content_str.encode('utf-8')

    if not doc_content_bytes:
        print("No content provided or read. Using default dummy content.")
        doc_content_str = "Default dummy content as no other content was provided."
        doc_content_bytes = doc_content_str.encode('utf-8')


    try:
        archiver_system.archive_document(doc_id, doc_content_bytes, archiver_name, viewer_names)

        # --- Document Retrieval Demo ---
        retrieve_choice = input(f"\nDo you want to retrieve document '{doc_id}'? (yes/no): ").lower()
        if retrieve_choice == 'yes' or retrieve_choice == 'y':
            user_to_retrieve = input(f"Enter user ID to retrieve (e.g., '{archiver_name}', '{viewer_names[1]}'): ")
            retrieved_content = archiver_system.retrieve_document(doc_id, user_to_retrieve)
            if retrieved_content:
                print(f"\nSuccessfully retrieved content:\n'{retrieved_content}'")
            else:
                print("\nDocument retrieval failed.")
        else:
            print("Skipping retrieval demo.")

    except ValueError as e:
        print(f"\nError during archiving/retrieval demo: {e}")
    except Exception as e:
        print(f"\nAn unexpected error occurred: {e}")

    while True:
        performance_test_input = ""
        
        performance_test_input = input("\nRun performance test? [y/n]: ").lower()
        if performance_test_input == 'y':
            break
        elif performance_test_input == 'n':
            sys.exit(0)
        else:
            print("Invalid input. Please enter 'y' or 'n'.")

       
    # --- Run Performance Test ---
    performance_results = run_performance_test(archiver_system, key_manager, data_size_mb=100)

    print("\n--- Assessment of Cryptographic Solution Appropriateness (Secure Local Document Archiving) ---")
    print("\nKey Parameters from Performance Test:")
    print("| Parameter                           | Value                | Component(s) Involved       ")
    print("|-------------------------------------|----------------------|-----------------------------")
    print(f"| Data Size Tested                    | {performance_results['data_size_mb']} MB               | Document Content            ")
    print(f"| Total Archiving Latency             | {performance_results['total_archiving_time']:.4f} seconds       | All Archiving Steps         ")
    print(f"| Total Retrieval Latency             | {performance_results['total_retrieval_time']:.4f} seconds       | All Retrieval Steps         ")
    print(f"|   - Hashing Time (SHA-512)          | {performance_results['hash_time']:.6f} seconds     | SHA-512                     ")
    print(f"|   - AES Key Generation Time         | {performance_results['aes_key_gen_time']:.6f} seconds     | OS.urandom                  ")
    print(f"|   - AES Encryption Time             | {performance_results['aes_encrypt_time']:.4f} seconds       | AES-256 GCM                 ")
    print(f"|   - ECDSA Signing Time              | {performance_results['ecdsa_sign_time']:.6f} seconds     | ECDSA (SECP384R1, SHA-512)  ")
    print(f"|   - RSA Encrypt Keys Time ({len(viewer_names)} users) | {performance_results['rsa_encrypt_keys_time']:.6f} seconds     | RSA (OAEP)                  ")
    print(f"|   - RSA Decrypt Key Time            | {performance_results['rsa_decrypt_key_time']:.6f} seconds     | RSA (OAEP)                  ")
    print(f"|   - AES Decryption Time             | {performance_results['aes_decrypt_time']:.4f} seconds       | AES-256 GCM                 ")
    print(f"|   - Re-Hashing Time                 | {performance_results['rehash_time']:.6f} seconds     | SHA-512                     ")
    print(f"|   - ECDSA Verification Time         | {performance_results['ecdsa_verify_time']:.6f} seconds     | ECDSA (SECP384R1, SHA-512)  ")
    print(f"| Encryption Throughput               | {performance_results['encryption_throughput_mbps']:.2f} MB/s         | AES-256 GCM                 ")
    print(f"| Decryption Throughput               | {performance_results['decryption_throughput_mbps']:.2f} MB/s          | AES-256 GCM                 ")
    print("|-------------------------------------|----------------------|-----------------------------")