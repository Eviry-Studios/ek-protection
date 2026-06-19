"""
ekprotection.scanner.hasher
=============================
Utilitários de hash para o scanner.

Fornece:
  - sha256_file()  — hash de arquivo em chunks (sem carregar tudo em RAM)
  - sha256_bytes() — hash de bytes em memória
  - is_elf()       — detecta binários ELF pelo magic number
  - is_script()    — detecta scripts pelo shebang
  - file_entropy() — entropia de Shannon (detecta packed/cifrado)
"""

from __future__ import annotations

import math
import os
from pathlib import Path
from typing  import Optional

CHUNK_SIZE = 65_536   # 64 KB por chunk


def sha256_file(path: str | Path, max_bytes: Optional[int] = None) -> str:
    """
    Calcula SHA-256 de um arquivo lendo em chunks de 64KB.
    Nunca carrega o arquivo inteiro em RAM.

    max_bytes: se definido, lê no máximo esse número de bytes
               (útil para arquivos muito grandes onde uma assinatura
               parcial é suficiente para identificar ameaças conhecidas).

    Retorna a string hexadecimal do hash.
    Lança OSError/PermissionError se o arquivo não puder ser lido.
    """
    import hashlib
    h       = hashlib.sha256()
    read    = 0

    with open(path, "rb") as fh:
        while True:
            remaining = (max_bytes - read) if max_bytes else CHUNK_SIZE
            chunk     = fh.read(min(CHUNK_SIZE, remaining))
            if not chunk:
                break
            h.update(chunk)
            read += len(chunk)
            if max_bytes and read >= max_bytes:
                break

    return h.hexdigest()


def sha256_bytes(data: bytes) -> str:
    """Hash SHA-256 de bytes em memória."""
    import hashlib
    return hashlib.sha256(data).hexdigest()


def is_elf(path: str | Path) -> bool:
    """
    Retorna True se o arquivo começa com o magic ELF (0x7f 'ELF').
    Não lança exceção — retorna False se não puder ler.
    """
    try:
        with open(path, "rb") as fh:
            return fh.read(4) == b"\x7fELF"
    except (OSError, PermissionError):
        return False


def is_script(path: str | Path) -> bool:
    """
    Retorna True se o arquivo começa com shebang (#!).
    """
    try:
        with open(path, "rb") as fh:
            return fh.read(2) == b"#!"
    except (OSError, PermissionError):
        return False


def file_entropy(path: str | Path, sample_bytes: int = 65_536) -> float:
    """
    Calcula a entropia de Shannon de até sample_bytes do arquivo.
    Resultado entre 0.0 (todos bytes iguais) e 8.0 (aleatório perfeito).

    Valores acima de 7.2 indicam conteúdo comprimido, cifrado ou packed —
    sinal de alerta para executáveis.
    """
    try:
        with open(path, "rb") as fh:
            data = fh.read(sample_bytes)
    except (OSError, PermissionError):
        return 0.0

    if not data:
        return 0.0

    freq   = [0] * 256
    for byte in data:
        freq[byte] += 1

    length  = len(data)
    entropy = 0.0
    for count in freq:
        if count == 0:
            continue
        p        = count / length
        entropy -= p * math.log2(p)

    return entropy
