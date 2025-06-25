from threatcorrelator.country_map import COUNTRY_MAP
from typing import Optional

def country_lookup(iso_code: str) -> Optional[str]:
    """Return the full country name for a given ISO code, or None if not found."""
    return COUNTRY_MAP.get(iso_code)
