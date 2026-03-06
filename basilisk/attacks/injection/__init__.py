"""Basilisk injection attack sub-modules."""

from basilisk.attacks.injection.direct import DirectInjection
from basilisk.attacks.injection.indirect import IndirectInjection
from basilisk.attacks.injection.multilingual import MultilingualInjection
from basilisk.attacks.injection.encoding import EncodingInjection
from basilisk.attacks.injection.split import SplitPayloadInjection

__all__ = [
    "DirectInjection",
    "IndirectInjection",
    "MultilingualInjection",
    "EncodingInjection",
    "SplitPayloadInjection",
]
