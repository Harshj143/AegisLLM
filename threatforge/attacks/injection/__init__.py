"""ThreatForge injection attack sub-modules."""

from threatforge.attacks.injection.direct import DirectInjection
from threatforge.attacks.injection.indirect import IndirectInjection
from threatforge.attacks.injection.multilingual import MultilingualInjection
from threatforge.attacks.injection.encoding import EncodingInjection
from threatforge.attacks.injection.split import SplitPayloadInjection

__all__ = [
    "DirectInjection",
    "IndirectInjection",
    "MultilingualInjection",
    "EncodingInjection",
    "SplitPayloadInjection",
]
