"""ekprotection.scanner — On-demand file scanner."""

from .hasher     import sha256_file, sha256_bytes, is_elf, is_script, file_entropy
from .signatures import SignatureDB
from .result     import FileScanResult, ScanReport, ScanVerdict
from .engine     import ScanEngine

__all__ = [
    "sha256_file", "sha256_bytes", "is_elf", "is_script", "file_entropy",
    "SignatureDB",
    "FileScanResult", "ScanReport", "ScanVerdict",
    "ScanEngine",
]
