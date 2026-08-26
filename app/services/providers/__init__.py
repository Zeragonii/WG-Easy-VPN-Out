
from __future__ import annotations
from dataclasses import dataclass
from .generic import GenericProviderAdapter
from .pia import PIAProviderAdapter

@dataclass(frozen=True, slots=True)
class ProviderMatch:
    adapter: object
    confidence: str
    reason: str

ADAPTERS = (PIAProviderAdapter(),)

def detect_provider(endpoint_host: str | None, content: str = "") -> ProviderMatch:
    for adapter in ADAPTERS:
        match = adapter.detect(endpoint_host, content)
        if match:
            confidence, reason = match
            return ProviderMatch(adapter=adapter, confidence=confidence, reason=reason)

    return ProviderMatch(
        adapter=GenericProviderAdapter(),
        confidence="none",
        reason="No known provider signature matched.",
    )
