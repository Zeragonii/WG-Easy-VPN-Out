
from __future__ import annotations
from dataclasses import dataclass

@dataclass(frozen=True, slots=True)
class ProviderCapabilities:
    region_detection: bool = False
    dns_presets: bool = False
    endpoint_metadata: bool = True
    wireguard_metadata: bool = True

class ProviderAdapter:
    key = "generic"
    display_name = "Unknown"
    capabilities = ProviderCapabilities()

    def detect(self, endpoint_host: str | None, content: str):
        return None

    def region_hint(self, endpoint_host: str | None):
        return None

    def dns_presets(self):
        return ()
