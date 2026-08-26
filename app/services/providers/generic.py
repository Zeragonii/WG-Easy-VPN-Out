
from .base import ProviderAdapter, ProviderCapabilities

class GenericProviderAdapter(ProviderAdapter):
    key = "generic"
    display_name = "Unknown"
    capabilities = ProviderCapabilities(
        region_detection=False,
        dns_presets=False,
        endpoint_metadata=True,
        wireguard_metadata=True,
    )
