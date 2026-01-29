#!/usr/bin/env python3
"""
secertcert - Generate X.509 certificates or standalone keys with hidden data in RSA public keys.

This tool generates certificates or keys where data is embedded in the RSA modulus.
For large data, it automatically chunks across multiple files.

The hidden data is in the PUBLIC key - anyone can extract it by reading
the modulus bits.

Usage:
    # Hide a message in standalone keys 
    secertcert.py -m "Hello" -o ./output --mode keys

    # Hide a message in X.509 certificates
    secertcert.py -m "Hello" -o ./output --mode x509 -d example.com

    # Hide file contents across multiple keys
    secertcert.py -f secret.txt -o ./output --mode keys

    # Hide with encryption (auto-generated passphrase)
    secertcert.py -e -m "Secret message" -o ./output --mode keys

    # Hide with custom passphrase
    secertcert.py -p "my-secret-phrase" -m "Secret message" -o ./output --mode keys

    # Read hidden data from certificates or keys
    secertcert.py --read -i ./output

    # Read encrypted data
    secertcert.py --read -i ./output -p "4-orange-castle-river"

"""

import argparse
import json
import os
import secrets
import sys
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import List, Optional, Tuple

from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric.rsa import (
    RSAPrivateNumbers,
    RSAPublicNumbers,
)
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC


# ============================================================================
# Constants
# ============================================================================

# RSA modulus LSB is always 1 (odd), so we shift data left by 8 bits
# to avoid the LSB being corrupted. This gives us 15 usable bytes.
DATA_BITS = 128  # Total bits reserved in modulus
CHUNK_USABLE_BYTES = 15  # 128 bits - 8 bits for padding = 120 bits = 15 bytes
CHUNK_HEADER_SIZE = 4  # 2 bytes sequence + 2 bytes total
CHUNK_PAYLOAD_SIZE = CHUNK_USABLE_BYTES - CHUNK_HEADER_SIZE  # 11 bytes per cert

# Encryption constants
KDF_SALT = b"secertcert-v1-kdf-salt"
KDF_ITERATIONS = 100_000

# Word list for passphrase generation
WORDLIST = [
    "apple", "banana", "cherry", "dragon", "eagle", "falcon", "grape", "honey",
    "igloo", "jungle", "kiwi", "lemon", "mango", "nectar", "orange", "papaya",
    "quartz", "raven", "sunset", "tiger", "umbrella", "violet", "walnut", "xylophone",
    "yellow", "zebra", "anchor", "bridge", "castle", "delta", "ember", "forest",
    "garden", "harbor", "island", "jasper", "kettle", "lantern", "meadow", "north",
    "ocean", "planet", "quiver", "river", "silver", "temple", "unity", "valley",
    "winter", "xenon", "yearly", "zephyr", "aurora", "breeze", "coral", "dusk",
    "eclipse", "fossil", "glacier", "horizon", "indigo", "jupiter", "karma", "lotus",
]


# ============================================================================
# Encryption Functions
# ============================================================================

def generate_passphrase(num_words: int = 4) -> str:
    """
    Generate a random passphrase like "4-orange-castle-river".

    Format: <num_words>-<word1>-<word2>-...-<wordN>
    """
    words = [secrets.choice(WORDLIST) for _ in range(num_words)]
    return f"{num_words}-" + "-".join(words)


def derive_encryption_key(passphrase: str) -> bytes:
    """Derive 256-bit AES key from passphrase using PBKDF2."""
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=KDF_SALT,
        iterations=KDF_ITERATIONS,
    )
    return kdf.derive(passphrase.encode('utf-8'))


def encrypt_data(plaintext: bytes, key: bytes) -> bytes:
    """Encrypt with AES-256-GCM. Returns nonce + ciphertext + tag."""
    aesgcm = AESGCM(key)
    nonce = secrets.token_bytes(12)
    ciphertext = aesgcm.encrypt(nonce, plaintext, None)
    return nonce + ciphertext


def decrypt_data(encrypted: bytes, key: bytes) -> bytes:
    """Decrypt AES-256-GCM. Input is nonce + ciphertext + tag."""
    aesgcm = AESGCM(key)
    nonce = encrypted[:12]
    ciphertext = encrypted[12:]
    return aesgcm.decrypt(nonce, ciphertext, None)


# ============================================================================
# Chunk Data Structure
# ============================================================================

@dataclass
class ChunkInfo:
    """A chunk of data with sequence metadata."""
    sequence: int
    total: int
    payload: bytes


def chunk_data(data: bytes) -> List[ChunkInfo]:
    """Split data into chunks that fit in certificate moduli."""
    total = (len(data) + CHUNK_PAYLOAD_SIZE - 1) // CHUNK_PAYLOAD_SIZE
    if total == 0:
        total = 1

    if total > 65535:
        raise ValueError(f"Data too large: requires {total} chunks (max 65535)")

    chunks = []
    for i in range(total):
        start = i * CHUNK_PAYLOAD_SIZE
        end = start + CHUNK_PAYLOAD_SIZE
        payload = data[start:end]

        # Pad last chunk with zeros
        if len(payload) < CHUNK_PAYLOAD_SIZE:
            payload = payload + b'\x00' * (CHUNK_PAYLOAD_SIZE - len(payload))

        chunks.append(ChunkInfo(sequence=i, total=total, payload=payload))

    return chunks


def encode_chunk(chunk: ChunkInfo) -> bytes:
    """
    Encode chunk to 16 bytes for RSA modulus embedding.

    Format (15 usable bytes + 1 padding byte):
    [seq:2][total:2][payload:11][padding:1]

    The data is shifted left 8 bits to avoid LSB corruption.
    """
    header = chunk.sequence.to_bytes(2, 'big') + chunk.total.to_bytes(2, 'big')
    raw = header + chunk.payload  # 15 bytes
    value = int.from_bytes(raw, 'big')
    shifted = (value << 8) | 0x01  # LSB must be 1 for RSA
    return shifted.to_bytes(16, 'big')


def decode_chunk(data: bytes) -> ChunkInfo:
    """Decode 16 bytes from RSA modulus back to chunk."""
    value = int.from_bytes(data, 'big')
    shifted = value >> 8  # Remove padding byte
    raw = shifted.to_bytes(15, 'big')

    sequence = int.from_bytes(raw[:2], 'big')
    total = int.from_bytes(raw[2:4], 'big')
    payload = raw[4:4 + CHUNK_PAYLOAD_SIZE]
    return ChunkInfo(sequence=sequence, total=total, payload=payload)


# ============================================================================
# RSA Key Generation with Hidden Data
# ============================================================================

def miller_rabin(n: int, k: int = 20) -> bool:
    """Miller-Rabin primality test."""
    if n < 2:
        return False
    if n == 2 or n == 3:
        return True
    if n % 2 == 0:
        return False

    # Write n-1 as 2^r * d
    r, d = 0, n - 1
    while d % 2 == 0:
        r += 1
        d //= 2

    for _ in range(k):
        a = secrets.randbelow(n - 3) + 2
        x = pow(a, d, n)
        if x == 1 or x == n - 1:
            continue
        for _ in range(r - 1):
            x = pow(x, 2, n)
            if x == n - 1:
                break
        else:
            return False
    return True


def generate_prime(bit_size: int) -> int:
    """Generate a random prime of given bit size."""
    for _ in range(100000):
        candidate = secrets.randbits(bit_size - 1)
        candidate |= (1 << (bit_size - 1)) | 1  # Set MSB and LSB
        if miller_rabin(candidate):
            return candidate
    raise ValueError("Could not find prime")


def generate_rsa_key_with_hidden_data(
    hidden_data: bytes,
    key_size: int = 2048,
    data_bits: int = DATA_BITS
) -> Tuple:
    """
    Generate RSA key with hidden data embedded in the modulus.

    The lower bits of n = p * q will contain our hidden data.
    This is done by choosing p such that (p * q) mod 2^data_bits = target.

    Args:
        hidden_data: 16 bytes to embed (already encoded chunk)
        key_size: RSA key size (2048 or 4096)
        data_bits: Bits reserved for hidden data

    Returns:
        Tuple of (private_key, n) where n is the modulus containing hidden data
    """
    if len(hidden_data) != 16:
        raise ValueError(f"Hidden data must be exactly 16 bytes, got {len(hidden_data)}")

    prime_bits = key_size // 2
    target = int.from_bytes(hidden_data, 'big')
    mask = (1 << data_bits) - 1

    # Generate fixed prime q
    q = generate_prime(prime_bits)

    # Calculate required lower bits for p
    # We want: (p * q) mod 2^data_bits = target
    # So: p mod 2^data_bits = target * q^(-1) mod 2^data_bits
    q_inv = pow(q, -1, 1 << data_bits)
    p_lower = (target * q_inv) & mask

    # Search for prime p with those lower bits
    upper_bits = prime_bits - data_bits
    for _ in range(100000):
        upper = secrets.randbits(upper_bits - 1)
        upper |= (1 << (upper_bits - 1))
        p_candidate = (upper << data_bits) | p_lower

        if p_candidate.bit_length() != prime_bits:
            continue

        if miller_rabin(p_candidate):
            p = p_candidate
            break
    else:
        raise ValueError("Could not find suitable prime")

    if p < q:
        p, q = q, p

    n = p * q
    e = 65537
    phi_n = (p - 1) * (q - 1)
    d = pow(e, -1, phi_n)
    dp = d % (p - 1)
    dq = d % (q - 1)
    qinv = pow(q, -1, p)

    public_numbers = RSAPublicNumbers(e, n)
    private_numbers = RSAPrivateNumbers(p, q, d, dp, dq, qinv, public_numbers)
    private_key = private_numbers.private_key(default_backend())

    return private_key, n


def extract_from_modulus(n: int, data_bits: int = DATA_BITS) -> bytes:
    """Extract hidden data from RSA modulus. No private key needed!"""
    mask = (1 << data_bits) - 1
    data_int = n & mask
    return data_int.to_bytes(16, 'big')


# ============================================================================
# Certificate Generation
# ============================================================================

def create_certificate(
    private_key,
    domain: str,
    sequence: int,
    validity_days: int = 365
) -> x509.Certificate:
    """Create a self-signed certificate."""
    subject = x509.Name([
        x509.NameAttribute(x509.oid.NameOID.COUNTRY_NAME, "US"),
        x509.NameAttribute(x509.oid.NameOID.COMMON_NAME, domain),
    ])

    now = datetime.now(timezone.utc)
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(subject)
        .public_key(private_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now)
        .not_valid_after(now + timedelta(days=validity_days))
        .add_extension(
            x509.SubjectAlternativeName([x509.DNSName(domain)]),
            critical=False
        )
        .sign(private_key, hashes.SHA256())
    )
    return cert


# ============================================================================
# Main Functions
# ============================================================================

def generate_certificates(
    data: bytes,
    output_dir: str,
    domain: str = "example.com",
    mode: str = "x509",
    verbose: bool = True,
    passphrase: Optional[str] = None,
    encrypt: bool = False
) -> Tuple[List[str], Optional[str]]:
    """
    Generate certificates or keys with hidden data.

    Args:
        data: Raw bytes to hide
        output_dir: Directory to write certificates/keys
        domain: Domain for certificates (only used in x509 mode)
        mode: Generation mode - "x509" for certificates, "keys" for standalone keys
        verbose: Print progress
        passphrase: Passphrase for encryption (if provided, data will be encrypted)
        encrypt: If True and passphrase is None, auto-generate passphrase

    Returns:
        Tuple of (list of generated file paths, passphrase if encryption was used)
    """
    os.makedirs(output_dir, exist_ok=True)

    # Handle encryption
    used_passphrase = None
    original_size = len(data)

    if passphrase or encrypt:
        if passphrase:
            used_passphrase = passphrase
        else:
            used_passphrase = generate_passphrase()

        # Derive key and encrypt
        key = derive_encryption_key(used_passphrase)

        # Prepend original length (4 bytes) so we know exact size after decryption
        length_bytes = len(data).to_bytes(4, 'big')
        data = encrypt_data(length_bytes + data, key)

        if verbose:
            print(f"Encryption: enabled")
            print(f"Original size: {original_size} bytes -> Encrypted: {len(data)} bytes")

    # Chunk the data
    chunks = chunk_data(data)

    if verbose:
        print(f"Mode: {mode}")
        print(f"Data size: {len(data)} bytes")
        print(f"Chunks needed: {len(chunks)}")
        print(f"Payload per chunk: {CHUNK_PAYLOAD_SIZE} bytes")
        print()

    file_paths = []
    metadata = {
        "mode": mode,
        "total_chunks": len(chunks),
        "data_size": len(data),
        "encrypted": used_passphrase is not None,
        "original_size": original_size if used_passphrase else len(data),
        "files": []
    }

    # Add domain to metadata only for x509 mode
    if mode == "x509":
        metadata["domain"] = domain

    for i, chunk in enumerate(chunks):
        if verbose:
            item_type = "certificate" if mode == "x509" else "key pair"
            print(f"Generating {item_type} {i + 1}/{len(chunks)}...", end=" ", flush=True)

        # Encode chunk to bytes for embedding
        chunk_bytes = encode_chunk(chunk)

        # Generate RSA key with hidden data
        private_key, n = generate_rsa_key_with_hidden_data(chunk_bytes)

        file_entry = {
            "sequence": i,
        }

        if mode == "x509":
            # Create certificate
            cert = create_certificate(private_key, domain, i)

            # Save certificate
            cert_filename = f"cert_{i:04d}.pem"
            cert_path = os.path.join(output_dir, cert_filename)
            with open(cert_path, "wb") as f:
                f.write(cert.public_bytes(serialization.Encoding.PEM))

            file_paths.append(cert_path)
            file_entry["cert_file"] = cert_filename

            # Save private key (optional, for verification)
            key_filename = f"key_{i:04d}.pem"
            key_path = os.path.join(output_dir, key_filename)
            with open(key_path, "wb") as f:
                f.write(private_key.private_bytes(
                    serialization.Encoding.PEM,
                    serialization.PrivateFormat.PKCS8,
                    serialization.NoEncryption()
                ))
            file_entry["key_file"] = key_filename
        else:
            # keys mode - save public and private keys
            pub_filename = f"pub_{i:04d}.pem"
            pub_path = os.path.join(output_dir, pub_filename)
            with open(pub_path, "wb") as f:
                f.write(private_key.public_key().public_bytes(
                    serialization.Encoding.PEM,
                    serialization.PublicFormat.SubjectPublicKeyInfo
                ))

            priv_filename = f"priv_{i:04d}.pem"
            priv_path = os.path.join(output_dir, priv_filename)
            with open(priv_path, "wb") as f:
                f.write(private_key.private_bytes(
                    serialization.Encoding.PEM,
                    serialization.PrivateFormat.PKCS8,
                    serialization.NoEncryption()
                ))

            file_paths.append(pub_path)
            file_entry["pub_file"] = pub_filename
            file_entry["priv_file"] = priv_filename

        metadata["files"].append(file_entry)

        if verbose:
            print("done")

    # Save metadata
    metadata_path = os.path.join(output_dir, "metadata.json")
    with open(metadata_path, "w") as f:
        json.dump(metadata, f, indent=2)

    if verbose:
        print()
        item_type = "certificates" if mode == "x509" else "key pairs"
        print(f"Generated {len(file_paths)} {item_type} in {output_dir}/")
        print(f"Metadata saved to {metadata_path}")

    return file_paths, used_passphrase


def read_certificates(
    input_dir: str,
    verbose: bool = True,
    passphrase: Optional[str] = None
) -> bytes:
    """
    Read and reassemble hidden data from certificates or standalone keys.

    Args:
        input_dir: Directory containing certificates or keys
        verbose: Print progress
        passphrase: Passphrase for decryption (required if data was encrypted)

    Returns:
        Original data bytes
    """
    # Load metadata
    metadata_path = os.path.join(input_dir, "metadata.json")
    mode = "x509"  # default
    pub_files = []
    encrypted = False

    if os.path.exists(metadata_path):
        with open(metadata_path) as f:
            metadata = json.load(f)

        mode = metadata.get("mode", "x509")
        encrypted = metadata.get("encrypted", False)

        if mode == "x509":
            # Legacy format compatibility
            if "certificates" in metadata:
                pub_files = [c["cert_file"] for c in metadata["certificates"]]
            else:
                pub_files = [f["cert_file"] for f in metadata["files"]]
        else:
            # keys mode
            pub_files = [f["pub_file"] for f in metadata["files"]]
    else:
        # Fall back to glob patterns
        cert_files = sorted(Path(input_dir).glob("cert_*.pem"))
        pub_key_files = sorted(Path(input_dir).glob("pub_*.pem"))

        if cert_files:
            mode = "x509"
            pub_files = [f.name for f in cert_files]
        elif pub_key_files:
            mode = "keys"
            pub_files = [f.name for f in pub_key_files]
        else:
            raise ValueError(f"No certificates or public keys found in {input_dir}")

    if not pub_files:
        raise ValueError(f"No files found in {input_dir}")

    if verbose:
        item_type = "certificates" if mode == "x509" else "public keys"
        print(f"Mode: {mode}")
        print(f"Found {len(pub_files)} {item_type}")
        if encrypted:
            print(f"Encrypted: yes")

    # Check if passphrase is needed
    if encrypted and not passphrase:
        raise ValueError("Data is encrypted. Please provide passphrase with -p/--passphrase")

    chunks = []
    for pub_file in pub_files:
        pub_path = os.path.join(input_dir, pub_file)

        # Load public key
        with open(pub_path, "rb") as f:
            pem_data = f.read()

        if mode == "x509":
            # Load from certificate
            cert = x509.load_pem_x509_certificate(pem_data)
            public_key = cert.public_key()
        else:
            # Load standalone public key
            public_key = serialization.load_pem_public_key(pem_data)

        # Extract modulus
        n = public_key.public_numbers().n

        # Extract hidden data from modulus
        chunk_bytes = extract_from_modulus(n)

        # Decode chunk
        chunk = decode_chunk(chunk_bytes)
        chunks.append(chunk)

        if verbose:
            print(f"  {pub_file}: chunk {chunk.sequence + 1}/{chunk.total}")

    # Sort by sequence and reassemble
    chunks.sort(key=lambda c: c.sequence)

    # Verify we have all chunks
    total = chunks[0].total
    sequences = {c.sequence for c in chunks}
    missing = set(range(total)) - sequences
    if missing:
        raise ValueError(f"Missing chunks: {sorted(missing)}")

    # Reassemble data
    raw_data = b''.join(c.payload for c in chunks)

    # Remove trailing zeros (padding)
    data = raw_data.rstrip(b'\x00')

    if verbose:
        print()
        print(f"Reassembled {len(data)} bytes from {len(chunks)} chunks")

    # Decrypt if needed
    if encrypted or passphrase:
        if not passphrase:
            raise ValueError("Data appears to be encrypted but no passphrase provided")

        try:
            key = derive_encryption_key(passphrase)
            decrypted = decrypt_data(data, key)

            # Extract original length (first 4 bytes)
            original_length = int.from_bytes(decrypted[:4], 'big')
            data = decrypted[4:4 + original_length]

            if verbose:
                print(f"Decrypted: {len(data)} bytes")
        except Exception as e:
            raise ValueError(f"Decryption failed. Wrong passphrase? Error: {e}")

    return data


# ============================================================================
# CLI
# ============================================================================

def main():
    parser = argparse.ArgumentParser(
        description="Generate certificates or keys with hidden data in RSA public keys",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Hide a message in X.509 certificates
  %(prog)s -m "Hello, World!" -o ./output --mode x509 -d example.com

  # Hide a message in standalone keys (for Rekor/Sigstore)
  %(prog)s -m "Hello, World!" -o ./output --mode keys

  # Hide file contents in keys
  %(prog)s -f secret.txt -o ./output --mode keys

  # Hide with encryption (auto-generated passphrase)
  %(prog)s -e -m "Secret message" -o ./output --mode keys

  # Hide with custom passphrase
  %(prog)s -p "my-secret-phrase" -m "Secret message" -o ./output --mode keys

  # Read hidden data (prints to stdout if < 10KB text)
  %(prog)s --read -i ./output

  # Read encrypted data
  %(prog)s --read -i ./output -p "4-orange-castle-river"

  # Read and save to file (required for binary or large data)
  %(prog)s --read -i ./output -o recovered.txt

        """
    )

    # Mode
    parser.add_argument("--read", action="store_true",
                        help="Read mode: extract hidden data from certificates or keys")

    # Input options
    parser.add_argument("-m", "--message", type=str,
                        help="Message to hide")
    parser.add_argument("-f", "--file", type=str,
                        help="File to hide")
    parser.add_argument("-i", "--input", type=str,
                        help="Input directory (for --read mode)")

    # Output options
    parser.add_argument("-o", "--output", type=str,
                        help="Output directory (generate mode) or file (read mode). "
                             "For --read, omit to print to stdout.")

    # Encryption options
    parser.add_argument("-p", "--passphrase", type=str,
                        help="Passphrase for encryption/decryption. "
                             "For generation: encrypt data with this passphrase. "
                             "For reading: decrypt data with this passphrase.")
    parser.add_argument("-e", "--encrypt", action="store_true",
                        help="Encrypt data with auto-generated passphrase (if -p not provided)")

    # Options
    parser.add_argument("--mode", type=str, choices=["x509", "keys"], default="x509",
                        help="Generation mode: x509 (certificates) or keys (standalone). Default: x509")
    parser.add_argument("-d", "--domain", type=str,
                        help="Domain for certificates (required for --mode x509, ignored for keys mode)")
    parser.add_argument("-q", "--quiet", action="store_true",
                        help="Quiet mode")

    args = parser.parse_args()
    verbose = not args.quiet

    # Max size to print to stdout (10KB)
    MAX_STDOUT_SIZE = 10 * 1024

    if args.read:
        # Read mode
        if not args.input:
            parser.error("--read requires --input directory")

        try:
            data = read_certificates(args.input, verbose=verbose, passphrase=args.passphrase)
        except ValueError as e:
            print(f"Error: {e}", file=sys.stderr)
            sys.exit(1)

        # Output
        if args.output:
            # Write to file
            with open(args.output, "wb") as f:
                f.write(data)
            if verbose:
                print(f"Saved to {args.output}")
        else:
            # Print to stdout
            if len(data) > MAX_STDOUT_SIZE:
                print(f"Error: Data too large for stdout ({len(data)} bytes, max {MAX_STDOUT_SIZE})",
                      file=sys.stderr)
                print(f"Use -o <file> to save to a file", file=sys.stderr)
                sys.exit(1)

            try:
                text = data.decode('utf-8')
                if verbose:
                    print()
                    print("=== Hidden Data ===")
                print(text)
            except UnicodeDecodeError:
                print(f"Error: Binary data cannot be printed to stdout ({len(data)} bytes)",
                      file=sys.stderr)
                print(f"Use -o <file> to save to a file", file=sys.stderr)
                sys.exit(1)

    else:
        # Generate mode
        if not args.output:
            parser.error("Generate mode requires --output directory")

        # Enforce --domain for x509 mode
        if args.mode == "x509" and not args.domain:
            parser.error("--mode x509 requires --domain to be specified")

        if args.message:
            data = args.message.encode('utf-8')
        elif args.file:
            with open(args.file, "rb") as f:
                data = f.read()
        else:
            parser.error("Provide --message or --file")

        if len(data) == 0:
            parser.error("No data to hide")

        # Determine if encryption is needed
        encrypt = args.encrypt or args.passphrase is not None

        file_paths, used_passphrase = generate_certificates(
            data=data,
            output_dir=args.output,
            domain=args.domain if args.domain else "example.com",
            mode=args.mode,
            verbose=verbose,
            passphrase=args.passphrase,
            encrypt=encrypt
        )

        # Display passphrase if auto-generated
        if used_passphrase and not args.passphrase:
            print()
            print("=" * 60)
            print("IMPORTANT: Save this passphrase to decrypt the data later!")
            print()
            print(f"  Passphrase: {used_passphrase}")
            print()
            print("=" * 60)
            print()
            print(f"To read: {sys.argv[0]} --read -i {args.output} -p \"{used_passphrase}\"")


if __name__ == "__main__":
    main()
