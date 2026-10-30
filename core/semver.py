"""
Semantic Versioning (SemVer) Engine
Provides integer-tuple parsing and range checking for software version evaluation.
"""

import re
from typing import Optional, Tuple


def parse_semver(v: str) -> Optional[Tuple[int, int, int]]:
    """
    Parse a version string into a (major, minor, patch) integer tuple.
    Handles formats like '1.26.1', 'v20.18.0', '8.2', '1.31.2-alpha'.
    """
    if not v:
        return None
    m = re.search(r'(\d+)\.(\d+)(?:\.(\d+))?', str(v))
    if m:
        major = int(m.group(1))
        minor = int(m.group(2))
        patch = int(m.group(3)) if m.group(3) is not None else 0
        return (major, minor, patch)
    return None


def in_range(ver_tuple: Optional[Tuple[int, int, int]],
             lo: Tuple[int, int, int],
             hi: Tuple[int, int, int]) -> bool:
    """
    Check if ver_tuple falls inclusively between lo and hi tuples (lo <= ver <= hi).
    Prevents false positives inherent to lexicographical string comparisons.
    """
    if not ver_tuple or not lo or not hi:
        return False
    return lo <= ver_tuple <= hi
