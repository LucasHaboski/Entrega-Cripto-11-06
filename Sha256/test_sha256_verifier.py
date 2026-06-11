import hashlib
import os
import sys
import tempfile
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).parent))

from sha256_verifier import compute_hash
from sha256_impl import sha256, sha256_file, pad_message


@pytest.fixture
def tmp_file(tmp_path):
    """Arquivo temporário com conteúdo conhecido."""
    content = b"Criptografia SHA256 - trabalho academico"
    p = tmp_path / "teste.txt"
    p.write_bytes(content)
    return p, content


@pytest.fixture
def empty_file(tmp_path):
    p = tmp_path / "vazio.bin"
    p.write_bytes(b"")
    return p


@pytest.fixture
def large_file(tmp_path):
    """Arquivo maior que um bloco SHA256 (> 64 bytes)."""
    content = b"A" * 10_000
    p = tmp_path / "grande.bin"
    p.write_bytes(content)
    return p, content


class TestComputeHash:
    def test_hash_matches_hashlib(self, tmp_file):
        p, content = tmp_file
        expected = hashlib.sha256(content).hexdigest()
        assert compute_hash(str(p)) == expected

    def test_hash_is_64_hex_chars(self, tmp_file):
        p, _ = tmp_file
        result = compute_hash(str(p))
        assert len(result) == 64
        assert all(c in "0123456789abcdef" for c in result)

    def test_empty_file_known_hash(self, empty_file):
        expected = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        assert compute_hash(str(empty_file)) == expected

    def test_large_file(self, large_file):
        p, content = large_file
        expected = hashlib.sha256(content).hexdigest()
        assert compute_hash(str(p)) == expected

    def test_different_files_different_hashes(self, tmp_path):
        f1 = tmp_path / "a.txt"
        f2 = tmp_path / "b.txt"
        f1.write_bytes(b"conteudo A")
        f2.write_bytes(b"conteudo B")
        assert compute_hash(str(f1)) != compute_hash(str(f2))

    def test_same_content_same_hash(self, tmp_path):
        """Determinismo: mesmo conteúdo, mesmo hash."""
        f1 = tmp_path / "c1.txt"
        f2 = tmp_path / "c2.txt"
        f1.write_bytes(b"igual")
        f2.write_bytes(b"igual")
        assert compute_hash(str(f1)) == compute_hash(str(f2))

    def test_one_byte_change_changes_hash(self, tmp_path):
        """Avalanche: uma mudança mínima altera o hash completamente."""
        f1 = tmp_path / "orig.bin"
        f2 = tmp_path / "mod.bin"
        f1.write_bytes(b"hello world")
        f2.write_bytes(b"hello World")
        h1 = compute_hash(str(f1))
        h2 = compute_hash(str(f2))
        assert h1 != h2


class TestSha256Impl:
    """Testa a implementação contra vetores do NIST."""

    NIST_VECTORS = [
        (b"", "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"),
        (b"abc", "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"),
        (b"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq",
         "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1"),
    ]

    @pytest.mark.parametrize("message,expected", NIST_VECTORS)
    def test_nist_vectors(self, message, expected):
        assert sha256(message) == expected

    def test_matches_hashlib_for_arbitrary_data(self):
        data = b"Verificador SHA256 - Criptografia 2026"
        assert sha256(data) == hashlib.sha256(data).hexdigest()

    def test_matches_hashlib_for_binary_data(self):
        data = bytes(range(256))
        assert sha256(data) == hashlib.sha256(data).hexdigest()

    def test_matches_hashlib_large_data(self):
        data = b"repetir" * 1000
        assert sha256(data) == hashlib.sha256(data).hexdigest()

    def test_sha256_file_matches_compute_hash(self, tmp_file):
        p, _ = tmp_file
        assert sha256_file(str(p)) == compute_hash(str(p))


class TestPadding:
    def test_padded_length_is_multiple_of_64(self):
        for length in [0, 1, 55, 56, 63, 64, 65, 127, 128]:
            msg = b"x" * length
            padded = pad_message(msg)
            assert len(padded) % 64 == 0, (
                f"comprimento {length}: padding resultou em {len(padded)} bytes"
            )

    def test_padded_ends_with_original_length_in_bits(self):
        msg = b"abc"
        padded = pad_message(msg)
        import struct
        stored_bits = struct.unpack(">Q", padded[-8:])[0]
        assert stored_bits == len(msg) * 8


class TestChecksumFileRoundtrip:
    """Testa o ciclo completo: generate → check."""

    def test_roundtrip(self, tmp_path):
        """Gera um .sha256 e verifica que todos os arquivos passam."""
        files = []
        for i, content in enumerate([b"alfa", b"beta", b"gama"]):
            f = tmp_path / f"file{i}.txt"
            f.write_bytes(content)
            files.append(str(f))

        checksum_path = str(tmp_path / "out.sha256")

        lines = []
        for fp in files:
            h = compute_hash(fp)
            lines.append(f"{h}  {fp}")

        with open(checksum_path, "w") as fh:
            fh.write("\n".join(lines) + "\n")

        with open(checksum_path) as fh:
            for line in fh:
                line = line.strip()
                if not line:
                    continue
                stored_hash, filepath = line.split(None, 1)
                assert compute_hash(filepath.strip()) == stored_hash

    def test_tampered_file_detected(self, tmp_path):
        """Modificar um arquivo deve mudar seu hash."""
        f = tmp_path / "doc.txt"
        f.write_bytes(b"conteudo original")
        original_hash = compute_hash(str(f))

        f.write_bytes(b"conteudo ALTERADO")
        new_hash = compute_hash(str(f))

        assert original_hash != new_hash
