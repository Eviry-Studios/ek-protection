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


# H001: a implementação antiga sempre lia só os primeiros `sample_bytes`
# (64KB) a partir do início do arquivo — qualquer payload de alta entropia
# posicionado depois do byte 65536 nunca era visto, mesmo em arquivos
# pequenos (ex.: 64KB de padding de baixa entropia + payload cifrado/
# comprimido logo depois disso). Testado ao vivo antes do fix: 64KB de
# zeros + 200KB de dados aleatórios → entropia calculada 0.0 (deveria ser
# alta) — evasão de esforço zero, só prefixar qualquer coisa de baixa
# entropia antes do payload.
#
# Tentativa 1 (descartada): ler o arquivo inteiro até um limite generoso
# (4 MiB). Fecha o blind spot, mas testado ao vivo contra ~3900 arquivos
# reais do sistema (binários/libs de /usr/bin, /usr/lib, /opt) introduzia
# falso positivo NOVO em bibliotecas legítimas (libsamplerate.so.0.2.2:
# 6.93→7.69; libsamba-util.so.0.0.1: 4.84→7.42) — ler mais do arquivo só
# aumenta entropia medida em código compilado real, não é sinal de perigo.
#
# Fix adotado: mesmo orçamento total de 64KB de antes (sem custo extra de
# I/O), mas distribuído em 3 janelas (início/meio/fim) em vez de só
# início. Testado ao vivo contra os mesmos ~3900 arquivos reais do
# sistema comparando com o comportamento antigo: **zero falsos positivos
# novos**, e **15 falsos positivos que já existiam em produção hoje
# foram corrigidos de bônus** (ex. libgeonames.so.0.3.1: 7.309→6.973;
# vários .bc do JIT do Postgres 16 que também rodam nesta VPS: 7.2-7.33→
# 6.7-7.16). Testado com 5 e 8 janelas também: FP do libgeonames volta
# (7.29 e 7.37) — 3 janelas é o ponto certo, não aumentar sem remedir.
#
# Limitação conhecida que fica documentada, não resolvida hoje: ainda é
# possível diluir um payload real com padding desproporcional (testado:
# 500KB de padding + 100KB de payload aleatório no fim → 3.57, não
# dispara) — entropia é média sobre as janelas amostradas, não detecção
# de sub-região arbitrária. Resolver isso de verdade exigiria entropia
# por seção ELF (parsing de program headers), escopo maior que uma
# rodada.
_N_ENTROPY_CHUNKS = 3


def file_entropy(path: str | Path, sample_bytes: int = 65_536) -> float:
    """
    Calcula a entropia de Shannon de até sample_bytes do arquivo.
    Resultado entre 0.0 (todos bytes iguais) e 8.0 (aleatório perfeito).

    Arquivos até sample_bytes são lidos por completo. Arquivos maiores
    usam sample_bytes distribuídos em 3 janelas (início, meio, fim) em
    vez de só o início — mesmo custo de I/O de antes.

    Valores acima de 7.2 indicam conteúdo comprimido, cifrado ou packed —
    sinal de alerta para executáveis.
    """
    try:
        size = os.path.getsize(path)
    except OSError:
        return 0.0

    try:
        if size <= sample_bytes:
            with open(path, "rb") as fh:
                data = fh.read(sample_bytes)
        else:
            chunk_size = max(1, sample_bytes // _N_ENTROPY_CHUNKS)
            span       = size - chunk_size
            buf        = bytearray()
            with open(path, "rb") as fh:
                for i in range(_N_ENTROPY_CHUNKS):
                    offset = (span * i) // (_N_ENTROPY_CHUNKS - 1)
                    fh.seek(offset)
                    buf += fh.read(chunk_size)
            data = bytes(buf)
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
