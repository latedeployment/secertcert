# secertcert

Generate X.509 certificates or standalone RSA keys with hidden data embedded in RSA public keys.

# Disclaimer
_*This is just an experiment with using RSA, if you use it for something else, it's on you.*_


## Installation

```bash
pip install cryptography
```

## Usage

```
secertcert.py [OPTIONS]

Hide data:
  -m, --message TEXT    Message to hide
  -f, --file PATH       File to hide
  -o, --output DIR      Output directory (required)
  --mode {keys,x509}    Output format (default: x509)
  -d, --domain DOMAIN   Domain for X.509 certs (required for x509 mode)
  -e, --encrypt         Encrypt with auto-generated passphrase
  -p, --passphrase STR  Encrypt with custom passphrase

Read data:
  --read                Extract hidden data
  -i, --input DIR       Input directory (required for --read)
  -o, --output FILE     Save to file (optional, prints to stdout otherwise)
  -p, --passphrase STR  Passphrase for decryption (if encrypted)
```

### Quick Start

```bash
# Hide a message in keys
python secertcert.py -m "Hello!" -o ./output --mode keys

# Read it back
python secertcert.py --read -i ./output
```

### Hide in X.509 Certificates

```bash
# Requires a domain name
python secertcert.py -m "Secret message" -o ./output --mode x509 -d example.com

# Read it back
python secertcert.py --read -i ./output
```

### Hide a File

```bash
python secertcert.py -f secret.txt -o ./output --mode keys

# Save extracted data to file
python secertcert.py --read -i ./output -o recovered.txt
```

### With Encryption

```bash
# Auto-generate passphrase (will print something like "4-orange-castle-river")
python secertcert.py -e -m "Secret" -o ./output --mode keys

# Or use your own passphrase
python secertcert.py -p "my-secret-phrase" -m "Secret" -o ./output --mode keys

# Read encrypted data (passphrase required)
python secertcert.py --read -i ./output -p "4-orange-castle-river"
```


## Testing

```bash
# Install dev dependencies
pip install pytest

# Run all tests (~10 minutes, RSA key generation is slow)
pytest test_secertcert.py -v

# Run specific test class (faster)
pytest test_secertcert.py::TestEncryption -v
```

## Benchmarking

```bash
# Basic benchmark (10 to 10K chars)
python benchmark.py

# Include larger sizes (100K and 1M chars)
python benchmark.py --larger
```

## Output Structure

### Keys mode (--mode keys)
```
output/
├── pub_0000.pem     # Public key with chunk 0
├── priv_0000.pem    # Private key
├── pub_0001.pem     # Public key with chunk 1
├── priv_0001.pem
├── ...
└── metadata.json    # Chunk info and file list
```

### X.509 mode (--mode x509)
```
output/
├── cert_0000.pem    # Certificate with chunk 0
├── key_0000.pem     # Private key
├── cert_0001.pem    # Certificate with chunk 1
├── key_0001.pem
├── ...
└── metadata.json    # Chunk info, domain, and file list
```
