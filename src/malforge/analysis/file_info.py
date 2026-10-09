import hashlib
import math
from collections import Counter
from pathlib import Path
from typing import Any


def shannon_entropy(data: bytes) -> float:
    """Shannon entropy in bits per byte, from 0.0 to 8.0."""
    if not data:
        return 0.0
    length = len(data)
    return -sum((n / length) * math.log2(n / length) for n in Counter(data).values())


def file_metadata(path: Path, data: bytes) -> dict[str, Any]:
    return {
        "filename": path.name,
        "file_size": len(data),
        "md5": hashlib.md5(data).hexdigest(),
        "sha1": hashlib.sha1(data).hexdigest(),
        "sha256": hashlib.sha256(data).hexdigest(),
        "entropy": round(shannon_entropy(data), 4),
    }
