#!/usr/bin/env python3
"""
unit tests for secertcert.py

"""

import os
import shutil
import tempfile
import unittest
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import serialization

import secertcert


class TestChunkEncoding(unittest.TestCase):
    """Test chunk encoding and decoding."""

    def test_encode_decode_roundtrip(self):
        """Test that encode/decode is reversible."""
        chunk = secertcert.ChunkInfo(
            sequence=0,
            total=1,
            payload=b"Hello World"  # 11 bytes exactly
        )
        encoded = secertcert.encode_chunk(chunk)
        self.assertEqual(len(encoded), 16)

        decoded = secertcert.decode_chunk(encoded)
        self.assertEqual(decoded.sequence, chunk.sequence)
        self.assertEqual(decoded.total, chunk.total)
        self.assertEqual(decoded.payload, chunk.payload)

    def test_encode_decode_max_sequence(self):
        """Test max sequence number (65535)."""
        chunk = secertcert.ChunkInfo(
            sequence=65535,
            total=65535,
            payload=b"X" * secertcert.CHUNK_PAYLOAD_SIZE
        )
        encoded = secertcert.encode_chunk(chunk)
        decoded = secertcert.decode_chunk(encoded)
        self.assertEqual(decoded.sequence, 65535)
        self.assertEqual(decoded.total, 65535)

    def test_encode_decode_various_sequences(self):
        """Test various sequence numbers."""
        for seq in [0, 1, 100, 1000, 10000, 32767, 65534]:
            chunk = secertcert.ChunkInfo(
                sequence=seq,
                total=seq + 1,
                payload=b"A" * secertcert.CHUNK_PAYLOAD_SIZE
            )
            encoded = secertcert.encode_chunk(chunk)
            decoded = secertcert.decode_chunk(encoded)
            self.assertEqual(decoded.sequence, seq, f"Failed for sequence {seq}")
            self.assertEqual(decoded.total, seq + 1)

    def test_encoded_lsb_is_one(self):
        """Test that encoded chunk has LSB = 1 (required for RSA)."""
        chunk = secertcert.ChunkInfo(
            sequence=0,
            total=1,
            payload=b"Hello World"
        )
        encoded = secertcert.encode_chunk(chunk)
        # LSB must be 1 for RSA modulus (odd number)
        self.assertEqual(encoded[-1] & 0x01, 0x01)


class TestChunkData(unittest.TestCase):
    """Test data chunking."""

    def test_chunk_small_data(self):
        """Test chunking data smaller than one chunk."""
        data = b"Hi"
        chunks = secertcert.chunk_data(data)
        self.assertEqual(len(chunks), 1)
        self.assertEqual(chunks[0].sequence, 0)
        self.assertEqual(chunks[0].total, 1)
        # Payload should be padded to CHUNK_PAYLOAD_SIZE
        self.assertEqual(len(chunks[0].payload), secertcert.CHUNK_PAYLOAD_SIZE)
        self.assertTrue(chunks[0].payload.startswith(b"Hi"))

    def test_chunk_exact_size(self):
        """Test data exactly CHUNK_PAYLOAD_SIZE."""
        data = b"X" * secertcert.CHUNK_PAYLOAD_SIZE
        chunks = secertcert.chunk_data(data)
        self.assertEqual(len(chunks), 1)
        self.assertEqual(chunks[0].payload, data)

    def test_chunk_multiple_chunks(self):
        """Test data requiring multiple chunks."""
        data = b"X" * (secertcert.CHUNK_PAYLOAD_SIZE * 3 + 5)
        chunks = secertcert.chunk_data(data)
        self.assertEqual(len(chunks), 4)
        for i, chunk in enumerate(chunks):
            self.assertEqual(chunk.sequence, i)
            self.assertEqual(chunk.total, 4)

    def test_chunk_empty_data(self):
        """Test chunking empty data (should create one chunk)."""
        data = b""
        chunks = secertcert.chunk_data(data)
        self.assertEqual(len(chunks), 1)
        self.assertEqual(chunks[0].sequence, 0)
        self.assertEqual(chunks[0].total, 1)

    def test_chunk_large_data(self):
        """Test chunking larger data."""
        data = b"Y" * 1000
        chunks = secertcert.chunk_data(data)
        expected_chunks = (1000 + secertcert.CHUNK_PAYLOAD_SIZE - 1) // secertcert.CHUNK_PAYLOAD_SIZE
        self.assertEqual(len(chunks), expected_chunks)


class TestRSAKeyGeneration(unittest.TestCase):
    """Test RSA key generation with hidden data."""

    def test_generate_key_with_hidden_data(self):
        """Test that hidden data is embedded in modulus."""
        # Note: LSB must be 1 (odd) for RSA. '!' = 0x21 = odd
        hidden = b"\x00\x01\x00\x01" + b"Hello World!"  # 16 bytes
        self.assertEqual(len(hidden), 16)

        private_key, n = secertcert.generate_rsa_key_with_hidden_data(hidden)

        # Extract data from modulus
        extracted = secertcert.extract_from_modulus(n)
        self.assertEqual(extracted, hidden)

    def test_generate_key_deterministic_extraction(self):
        """Test that extraction is deterministic."""
        # bytes(range(16)) ends with 15 = 0x0F (odd LSB)
        hidden = bytes(range(16))

        private_key, n = secertcert.generate_rsa_key_with_hidden_data(hidden)

        # Extract multiple times
        for _ in range(5):
            extracted = secertcert.extract_from_modulus(n)
            self.assertEqual(extracted, hidden)

    def test_generate_key_various_data(self):
        """Test with various hidden data patterns.

        Note: Hidden data must have LSB=1 (RSA modulus must be odd).
        In practice, encode_chunk() always sets LSB=1, so we test with
        properly formatted data here.
        """
        # Create test chunks with various payloads - encode_chunk ensures LSB=1
        test_payloads = [
            b"\x00" * secertcert.CHUNK_PAYLOAD_SIZE,  # All zeros payload
            b"\xff" * secertcert.CHUNK_PAYLOAD_SIZE,  # All ones payload
            bytes(range(secertcert.CHUNK_PAYLOAD_SIZE)),  # Sequential
            b"Hello World",  # ASCII (11 bytes)
            bytes([i * 17 % 256 for i in range(secertcert.CHUNK_PAYLOAD_SIZE)]),  # Mixed
        ]

        for payload in test_payloads:
            chunk = secertcert.ChunkInfo(sequence=0, total=1, payload=payload)
            hidden = secertcert.encode_chunk(chunk)

            with self.subTest(payload=payload[:8].hex()):
                private_key, n = secertcert.generate_rsa_key_with_hidden_data(hidden)
                extracted = secertcert.extract_from_modulus(n)
                self.assertEqual(extracted, hidden)

    def test_generate_key_size(self):
        """Test that generated key has correct size."""
        # 'A' = 0x41 = 65 (odd LSB)
        hidden = b"A" * 16
        private_key, n = secertcert.generate_rsa_key_with_hidden_data(hidden, key_size=2048)

        # Check key size (2048 bits = 256 bytes)
        self.assertGreaterEqual(n.bit_length(), 2047)
        self.assertLessEqual(n.bit_length(), 2048)

    def test_invalid_hidden_data_size(self):
        """Test that wrong data size raises error."""
        with self.assertRaises(ValueError):
            secertcert.generate_rsa_key_with_hidden_data(b"short")

        with self.assertRaises(ValueError):
            secertcert.generate_rsa_key_with_hidden_data(b"A" * 20)  # Too long

    def test_encode_chunk_always_sets_lsb(self):
        """Test that encode_chunk always produces odd LSB (required for RSA)."""
        # Test various payloads - encode_chunk must always produce odd result
        test_payloads = [
            b"\x00" * secertcert.CHUNK_PAYLOAD_SIZE,
            b"\xff" * secertcert.CHUNK_PAYLOAD_SIZE,
            b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00",  # 11 zeros
            b"Hello World",
        ]

        for payload in test_payloads:
            chunk = secertcert.ChunkInfo(sequence=0, total=1, payload=payload)
            encoded = secertcert.encode_chunk(chunk)
            # LSB must always be 1 for RSA
            self.assertEqual(encoded[-1] & 0x01, 1, f"LSB not set for payload: {payload}")


class TestEncryption(unittest.TestCase):
    """Test encryption and decryption functions."""

    def test_encrypt_decrypt_roundtrip(self):
        """Test encrypt/decrypt is reversible."""
        plaintext = b"Hello, World! This is a test message."
        key = secertcert.derive_encryption_key("test-passphrase")

        encrypted = secertcert.encrypt_data(plaintext, key)
        decrypted = secertcert.decrypt_data(encrypted, key)

        self.assertEqual(decrypted, plaintext)

    def test_encryption_adds_overhead(self):
        """Test that encryption adds expected overhead (nonce + tag)."""
        plaintext = b"Test"
        key = secertcert.derive_encryption_key("passphrase")

        encrypted = secertcert.encrypt_data(plaintext, key)

        # AES-GCM: 12 byte nonce + plaintext + 16 byte tag
        expected_size = 12 + len(plaintext) + 16
        self.assertEqual(len(encrypted), expected_size)

    def test_different_passphrases_produce_different_keys(self):
        """Test that different passphrases produce different keys."""
        key1 = secertcert.derive_encryption_key("passphrase1")
        key2 = secertcert.derive_encryption_key("passphrase2")

        self.assertNotEqual(key1, key2)

    def test_same_passphrase_produces_same_key(self):
        """Test that same passphrase always produces same key."""
        key1 = secertcert.derive_encryption_key("consistent")
        key2 = secertcert.derive_encryption_key("consistent")

        self.assertEqual(key1, key2)

    def test_wrong_passphrase_fails_decryption(self):
        """Test that wrong passphrase fails to decrypt."""
        plaintext = b"Secret data"
        key1 = secertcert.derive_encryption_key("correct")
        key2 = secertcert.derive_encryption_key("wrong")

        encrypted = secertcert.encrypt_data(plaintext, key1)

        with self.assertRaises(Exception):  # InvalidTag or similar
            secertcert.decrypt_data(encrypted, key2)

    def test_encrypt_empty_data(self):
        """Test encrypting empty data."""
        plaintext = b""
        key = secertcert.derive_encryption_key("passphrase")

        encrypted = secertcert.encrypt_data(plaintext, key)
        decrypted = secertcert.decrypt_data(encrypted, key)

        self.assertEqual(decrypted, plaintext)

    def test_encrypt_large_data(self):
        """Test encrypting larger data."""
        plaintext = b"X" * 10000
        key = secertcert.derive_encryption_key("passphrase")

        encrypted = secertcert.encrypt_data(plaintext, key)
        decrypted = secertcert.decrypt_data(encrypted, key)

        self.assertEqual(decrypted, plaintext)


class TestPassphraseGeneration(unittest.TestCase):
    """Test passphrase generation."""

    def test_generate_passphrase_format(self):
        """Test passphrase format."""
        passphrase = secertcert.generate_passphrase(4)

        parts = passphrase.split("-")
        self.assertEqual(len(parts), 5)  # count + 4 words
        self.assertEqual(parts[0], "4")

        for word in parts[1:]:
            self.assertIn(word, secertcert.WORDLIST)

    def test_generate_passphrase_different_lengths(self):
        """Test passphrase with different word counts."""
        for num_words in [2, 3, 4, 5, 6]:
            passphrase = secertcert.generate_passphrase(num_words)
            parts = passphrase.split("-")
            self.assertEqual(len(parts), num_words + 1)
            self.assertEqual(parts[0], str(num_words))

    def test_generate_passphrase_randomness(self):
        """Test that passphrases are random."""
        passphrases = [secertcert.generate_passphrase() for _ in range(100)]
        # Should be mostly unique (extremely unlikely to have duplicates)
        unique = set(passphrases)
        self.assertGreater(len(unique), 90)


class TestEndToEnd(unittest.TestCase):
    """End-to-end tests for certificate/key generation and reading."""

    def setUp(self):
        """Create temporary directory for test outputs."""
        self.test_dir = tempfile.mkdtemp()

    def tearDown(self):
        """Clean up temporary directory."""
        shutil.rmtree(self.test_dir)

    def test_generate_and_read_keys_mode(self):
        """Test generate and read in keys mode."""
        data = b"Hello, World!"
        output_dir = os.path.join(self.test_dir, "keys_test")

        file_paths, passphrase = secertcert.generate_certificates(
            data=data,
            output_dir=output_dir,
            mode="keys",
            verbose=False
        )

        self.assertGreater(len(file_paths), 0)
        self.assertIsNone(passphrase)

        # Read back
        recovered = secertcert.read_certificates(output_dir, verbose=False)
        self.assertEqual(recovered, data)

    def test_generate_and_read_x509_mode(self):
        """Test generate and read in x509 mode."""
        data = b"Certificate test data"
        output_dir = os.path.join(self.test_dir, "x509_test")

        file_paths, passphrase = secertcert.generate_certificates(
            data=data,
            output_dir=output_dir,
            mode="x509",
            domain="test.example.com",
            verbose=False
        )

        self.assertGreater(len(file_paths), 0)
        self.assertIsNone(passphrase)

        # Read back
        recovered = secertcert.read_certificates(output_dir, verbose=False)
        self.assertEqual(recovered, data)

    def test_generate_and_read_with_encryption(self):
        """Test generate and read with encryption."""
        data = b"Encrypted secret message"
        output_dir = os.path.join(self.test_dir, "encrypted_test")
        passphrase = "my-test-passphrase"

        file_paths, used_passphrase = secertcert.generate_certificates(
            data=data,
            output_dir=output_dir,
            mode="keys",
            verbose=False,
            passphrase=passphrase
        )

        self.assertEqual(used_passphrase, passphrase)

        # Read back with passphrase
        recovered = secertcert.read_certificates(
            output_dir,
            verbose=False,
            passphrase=passphrase
        )
        self.assertEqual(recovered, data)

    def test_generate_and_read_auto_passphrase(self):
        """Test generate with auto-generated passphrase."""
        data = b"Auto-encrypted message"
        output_dir = os.path.join(self.test_dir, "auto_encrypted_test")

        file_paths, used_passphrase = secertcert.generate_certificates(
            data=data,
            output_dir=output_dir,
            mode="keys",
            verbose=False,
            encrypt=True
        )

        self.assertIsNotNone(used_passphrase)
        self.assertIn("-", used_passphrase)  # Should be in word format

        # Read back with the auto-generated passphrase
        recovered = secertcert.read_certificates(
            output_dir,
            verbose=False,
            passphrase=used_passphrase
        )
        self.assertEqual(recovered, data)

    def test_read_encrypted_without_passphrase_fails(self):
        """Test that reading encrypted data without passphrase fails."""
        data = b"Secret"
        output_dir = os.path.join(self.test_dir, "no_pass_test")

        secertcert.generate_certificates(
            data=data,
            output_dir=output_dir,
            mode="keys",
            verbose=False,
            encrypt=True
        )

        with self.assertRaises(ValueError) as context:
            secertcert.read_certificates(output_dir, verbose=False)

        self.assertIn("passphrase", str(context.exception).lower())

    def test_read_encrypted_with_wrong_passphrase_fails(self):
        """Test that wrong passphrase fails."""
        data = b"Secret"
        output_dir = os.path.join(self.test_dir, "wrong_pass_test")

        secertcert.generate_certificates(
            data=data,
            output_dir=output_dir,
            mode="keys",
            verbose=False,
            passphrase="correct-passphrase"
        )

        with self.assertRaises(ValueError) as context:
            secertcert.read_certificates(
                output_dir,
                verbose=False,
                passphrase="wrong-passphrase"
            )

        self.assertIn("decryption", str(context.exception).lower())


class TestVariousDataSizes(unittest.TestCase):
    """Test with various data sizes."""

    def setUp(self):
        """Create temporary directory for test outputs."""
        self.test_dir = tempfile.mkdtemp()

    def tearDown(self):
        """Clean up temporary directory."""
        shutil.rmtree(self.test_dir)

    def test_single_byte(self):
        """Test with single byte."""
        self._test_roundtrip(b"X")

    def test_10_chars(self):
        """Test with 10 characters."""
        self._test_roundtrip(b"0123456789")

    def test_11_chars_exact_chunk(self):
        """Test with exactly CHUNK_PAYLOAD_SIZE bytes."""
        data = b"A" * secertcert.CHUNK_PAYLOAD_SIZE
        self._test_roundtrip(data)

    def test_12_chars_overflow(self):
        """Test with one byte more than CHUNK_PAYLOAD_SIZE."""
        data = b"B" * (secertcert.CHUNK_PAYLOAD_SIZE + 1)
        self._test_roundtrip(data)

    def test_100_chars(self):
        """Test with 100 characters."""
        data = b"C" * 100
        self._test_roundtrip(data)

    def test_1000_chars(self):
        """Test with 1000 characters."""
        data = b"D" * 1000
        self._test_roundtrip(data)

    def test_mixed_binary_data(self):
        """Test with binary data containing all byte values."""
        data = bytes(range(256))
        self._test_roundtrip(data)

    def test_unicode_message(self):
        """Test with unicode characters."""
        message = "Hello \u4e16\u754c \U0001F600 \u00e9\u00e8\u00ea"  # Chinese, emoji, accented
        data = message.encode('utf-8')
        self._test_roundtrip(data)

    def _test_roundtrip(self, data: bytes):
        """Helper to test roundtrip for given data."""
        output_dir = os.path.join(self.test_dir, f"test_{len(data)}")

        file_paths, _ = secertcert.generate_certificates(
            data=data,
            output_dir=output_dir,
            mode="keys",
            verbose=False
        )

        recovered = secertcert.read_certificates(output_dir, verbose=False)
        self.assertEqual(recovered, data)


class TestMetadataAndFiles(unittest.TestCase):
    """Test metadata and file generation."""

    def setUp(self):
        """Create temporary directory for test outputs."""
        self.test_dir = tempfile.mkdtemp()

    def tearDown(self):
        """Clean up temporary directory."""
        shutil.rmtree(self.test_dir)

    def test_metadata_file_created(self):
        """Test that metadata.json is created."""
        output_dir = os.path.join(self.test_dir, "metadata_test")

        secertcert.generate_certificates(
            data=b"Test",
            output_dir=output_dir,
            mode="keys",
            verbose=False
        )

        metadata_path = os.path.join(output_dir, "metadata.json")
        self.assertTrue(os.path.exists(metadata_path))

        import json
        with open(metadata_path) as f:
            metadata = json.load(f)

        self.assertEqual(metadata["mode"], "keys")
        self.assertEqual(metadata["total_chunks"], 1)
        self.assertIn("files", metadata)

    def test_metadata_encryption_flag(self):
        """Test that metadata includes encryption flag."""
        output_dir = os.path.join(self.test_dir, "enc_metadata_test")

        secertcert.generate_certificates(
            data=b"Test",
            output_dir=output_dir,
            mode="keys",
            verbose=False,
            encrypt=True
        )

        import json
        with open(os.path.join(output_dir, "metadata.json")) as f:
            metadata = json.load(f)

        self.assertTrue(metadata["encrypted"])

    def test_keys_mode_creates_pub_priv_files(self):
        """Test that keys mode creates pub_*.pem and priv_*.pem files."""
        output_dir = os.path.join(self.test_dir, "keys_files_test")

        secertcert.generate_certificates(
            data=b"Test data here",
            output_dir=output_dir,
            mode="keys",
            verbose=False
        )

        pub_files = list(Path(output_dir).glob("pub_*.pem"))
        priv_files = list(Path(output_dir).glob("priv_*.pem"))

        self.assertGreater(len(pub_files), 0)
        self.assertEqual(len(pub_files), len(priv_files))

    def test_x509_mode_creates_cert_key_files(self):
        """Test that x509 mode creates cert_*.pem and key_*.pem files."""
        output_dir = os.path.join(self.test_dir, "x509_files_test")

        secertcert.generate_certificates(
            data=b"Test data here",
            output_dir=output_dir,
            mode="x509",
            domain="example.com",
            verbose=False
        )

        cert_files = list(Path(output_dir).glob("cert_*.pem"))
        key_files = list(Path(output_dir).glob("key_*.pem"))

        self.assertGreater(len(cert_files), 0)
        self.assertEqual(len(cert_files), len(key_files))

        # Verify certificates are valid
        for cert_file in cert_files:
            with open(cert_file, "rb") as f:
                cert = x509.load_pem_x509_certificate(f.read())
            self.assertIsNotNone(cert)


class TestPrimality(unittest.TestCase):
    """Test primality testing functions."""

    def test_miller_rabin_known_primes(self):
        """Test Miller-Rabin with known primes."""
        primes = [2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37, 41, 43, 47,
                  53, 59, 61, 67, 71, 73, 79, 83, 89, 97, 104729]

        for p in primes:
            self.assertTrue(secertcert.miller_rabin(p), f"{p} should be prime")

    def test_miller_rabin_known_composites(self):
        """Test Miller-Rabin with known composites."""
        composites = [4, 6, 8, 9, 10, 12, 14, 15, 16, 18, 20, 21, 22, 24,
                      25, 26, 27, 28, 100, 1000, 561]  # 561 is Carmichael number

        for c in composites:
            self.assertFalse(secertcert.miller_rabin(c), f"{c} should be composite")

    def test_miller_rabin_edge_cases(self):
        """Test Miller-Rabin edge cases."""
        self.assertFalse(secertcert.miller_rabin(0))
        self.assertFalse(secertcert.miller_rabin(1))
        self.assertTrue(secertcert.miller_rabin(2))
        self.assertTrue(secertcert.miller_rabin(3))

    def test_generate_prime(self):
        """Test prime generation."""
        for bit_size in [128, 256, 512]:
            p = secertcert.generate_prime(bit_size)
            self.assertEqual(p.bit_length(), bit_size)
            self.assertTrue(secertcert.miller_rabin(p))


class TestEdgeCases(unittest.TestCase):
    """Test edge cases and error handling."""

    def setUp(self):
        """Create temporary directory for test outputs."""
        self.test_dir = tempfile.mkdtemp()

    def tearDown(self):
        """Clean up temporary directory."""
        shutil.rmtree(self.test_dir)

    def test_empty_input_directory(self):
        """Test reading from empty directory."""
        empty_dir = os.path.join(self.test_dir, "empty")
        os.makedirs(empty_dir)

        with self.assertRaises(ValueError):
            secertcert.read_certificates(empty_dir, verbose=False)

    def test_non_existent_directory(self):
        """Test reading from non-existent directory."""
        with self.assertRaises(Exception):
            secertcert.read_certificates("/nonexistent/path", verbose=False)

    def test_data_with_null_bytes(self):
        """Test data containing null bytes."""
        data = b"Hello\x00World\x00\x00End"
        output_dir = os.path.join(self.test_dir, "null_test")

        secertcert.generate_certificates(
            data=data,
            output_dir=output_dir,
            mode="keys",
            verbose=False
        )

        # Note: rstrip(b'\x00') in read_certificates will strip trailing nulls
        # So we test with data that doesn't end with null bytes
        data_no_trailing_null = b"Hello\x00World\x00\x00End"
        recovered = secertcert.read_certificates(output_dir, verbose=False)
        self.assertEqual(recovered, data_no_trailing_null)

    def test_whitespace_only_data(self):
        """Test data with only whitespace."""
        data = b"   \t\n\r  "
        output_dir = os.path.join(self.test_dir, "whitespace_test")

        secertcert.generate_certificates(
            data=data,
            output_dir=output_dir,
            mode="keys",
            verbose=False
        )

        recovered = secertcert.read_certificates(output_dir, verbose=False)
        self.assertEqual(recovered, data)

    def test_single_null_byte(self):
        """Test single null byte followed by data."""
        # Note: trailing null bytes get stripped, so we need non-null at end
        data = b"\x00\x00\x00ABC"
        output_dir = os.path.join(self.test_dir, "single_null_test")

        secertcert.generate_certificates(
            data=data,
            output_dir=output_dir,
            mode="keys",
            verbose=False
        )

        recovered = secertcert.read_certificates(output_dir, verbose=False)
        self.assertEqual(recovered, data)


class TestCLIArguments(unittest.TestCase):
    """Test CLI argument parsing (without actually running main)."""

    def test_argparse_setup(self):
        """Test that argparse is configured correctly."""
        import argparse

        # This is just to verify the module loads and has expected attributes
        self.assertTrue(hasattr(secertcert, 'main'))
        self.assertTrue(hasattr(secertcert, 'generate_certificates'))
        self.assertTrue(hasattr(secertcert, 'read_certificates'))


class TestMultipleChunks(unittest.TestCase):
    """Test with data requiring multiple chunks."""

    def setUp(self):
        """Create temporary directory for test outputs."""
        self.test_dir = tempfile.mkdtemp()

    def tearDown(self):
        """Clean up temporary directory."""
        shutil.rmtree(self.test_dir)

    def test_exactly_two_chunks(self):
        """Test data requiring exactly 2 chunks."""
        # 22 bytes = 2 chunks of 11 bytes each
        data = b"A" * (secertcert.CHUNK_PAYLOAD_SIZE * 2)
        self._test_multi_chunk(data, expected_chunks=2)

    def test_exactly_five_chunks(self):
        """Test data requiring exactly 5 chunks."""
        data = b"B" * (secertcert.CHUNK_PAYLOAD_SIZE * 5)
        self._test_multi_chunk(data, expected_chunks=5)

    def test_ten_chunks_with_remainder(self):
        """Test data requiring 10+ chunks with remainder."""
        data = b"C" * (secertcert.CHUNK_PAYLOAD_SIZE * 10 + 3)
        self._test_multi_chunk(data, expected_chunks=11)

    def _test_multi_chunk(self, data: bytes, expected_chunks: int):
        """Helper for multi-chunk tests."""
        output_dir = os.path.join(self.test_dir, f"chunks_{expected_chunks}")

        chunks = secertcert.chunk_data(data)
        self.assertEqual(len(chunks), expected_chunks)

        file_paths, _ = secertcert.generate_certificates(
            data=data,
            output_dir=output_dir,
            mode="keys",
            verbose=False
        )

        # Verify correct number of files
        self.assertEqual(len(file_paths), expected_chunks)

        # Verify roundtrip
        recovered = secertcert.read_certificates(output_dir, verbose=False)
        self.assertEqual(recovered, data)


if __name__ == "__main__":
    unittest.main(verbosity=2)
