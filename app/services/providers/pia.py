
from __future__ import annotations
import re
from .base import ProviderAdapter, ProviderCapabilities

class PIAProviderAdapter(ProviderAdapter):
    key = "pia"
    display_name = "Private Internet Access"
    capabilities = ProviderCapabilities(
        region_detection=True,
        dns_presets=True,
        endpoint_metadata=True,
        wireguard_metadata=True,
    )

    DOMAINS = ("privacy.network", "privateinternetaccess.com")

    PREFIXES = {
        "us": "US", "uk": "UK", "gb": "UK", "ca": "Canada",
        "de": "Germany", "fr": "France", "nl": "Netherlands",
        "ie": "Ireland", "au": "Australia", "jp": "Japan",
        "sg": "Singapore", "se": "Sweden", "ch": "Switzerland",
    }

    STANDALONE = {
        "ireland": "Ireland", "austria": "Austria", "belgium": "Belgium",
        "bulgaria": "Bulgaria", "denmark": "Denmark", "finland": "Finland",
        "france": "France", "germany": "Germany", "greece": "Greece",
        "iceland": "Iceland", "italy": "Italy", "norway": "Norway",
        "poland": "Poland", "portugal": "Portugal", "romania": "Romania",
        "singapore": "Singapore", "slovakia": "Slovakia",
        "slovenia": "Slovenia", "spain": "Spain", "sweden": "Sweden",
        "switzerland": "Switzerland",
    }

    def detect(self, endpoint_host: str | None, content: str):
        host = (endpoint_host or "").lower()
        if any(host.endswith(domain) for domain in self.DOMAINS):
            return ("high", f"Endpoint matches PIA domain: {endpoint_host}")
        if "private internet access" in (content or "").lower():
            return ("medium", "Configuration text references Private Internet Access.")
        return None

    def region_hint(self, endpoint_host: str | None):
        if not endpoint_host:
            return None

        first = endpoint_host.lower().split(".", 1)[0]
        tokens = [t for t in re.split(r"[-_]", first) if t]

        if first in self.STANDALONE:
            return self.STANDALONE[first]

        if len(tokens) >= 2 and tokens[0] in self.PREFIXES:
            country = self.PREFIXES[tokens[0]]
            remainder = tokens[1:]

            if remainder and remainder[-1] == "so":
                remainder = remainder[:-1]
                if remainder and remainder[0] == country.lower():
                    remainder = remainder[1:]
                if remainder:
                    location = " ".join(t.capitalize() for t in remainder)
                    return f"{country} · {location} · Streaming Optimized"
                return f"{country} · Streaming Optimized"

            location = " ".join(t.capitalize() for t in remainder)
            return f"{country} · {location}" if location else country

        return None

    def dns_presets(self):
        return (
            ("pia", "PIA DNS", "10.0.0.242"),
            ("pia_streaming", "PIA DNS + Streaming", "10.0.0.243"),
            ("pia_mace", "PIA DNS + MACE", "10.0.0.244"),
            ("pia_streaming_mace", "PIA DNS + Streaming + MACE", "10.0.0.241"),
        )
