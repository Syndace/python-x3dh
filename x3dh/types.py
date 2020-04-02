import base64
from enum import Enum
from typing import List, NamedTuple, Optional, Dict, Any, TypeVar, Type, Union

################
# Type Aliases #
################

# This type definition is far from optimal, but mypy doesn't support recurisve types yet (and I doubt it ever
# will).
JSONType = Union[None, bool, int, str, List[Any], Dict[str, Any]]

KeyPairSerialized = Dict[str, str]
SignedPreKeyPairSerialized = Dict[str, Union[KeyPairSerialized, str, int]]
StateSerialized = Dict[str, Union[
    None,
    str,
    KeyPairSerialized,
    SignedPreKeyPairSerialized,
    List[KeyPairSerialized]
]]

############################
# Structures (NamedTuples) #
############################

class Bundle(NamedTuple):
    """
    The bundle is a collection of public keys and signatures used by the X3DH protocol to achieve asynchronous
    key agreements while providing forward secrecy and cryptographic deniability. Parties that want to be
    available for X3DH key agreements have to publish their bundle somehow. Other parties can then use that
    bundle to perform a key agreement.
    """

    ik:      bytes
    spk:     bytes
    spk_sig: bytes
    opks:    List[bytes]

Bundle.ik.__doc__ = (
    "The public part of the identity key. Length and encoding depend on the curve (25519 vs. 448) and the"
    " type of key (Curve vs. Ed) used here."
)

Bundle.spk.__doc__ = (
    "The public part of the signed pre key. Length and encoding depend on the curve."
)

Bundle.spk_sig.__doc__ = (
    "The detached signature of the signed pre key created with the identity key. Length and encoding depend"
    " on the curve."
)

Bundle.opks.__doc__ = (
    "A list of public keys with one entry for each one-time pre key. Note that this list may be empty. Length"
    " and encoding depend on the curve."
)

class Header(NamedTuple):
    ik:  bytes
    ek:  bytes
    spk: bytes
    opk: Optional[bytes]

class SharedSecretActive(NamedTuple):
    shared_secret:   bytes
    associated_data: bytes
    header:          Header

class SharedSecretPassive(NamedTuple):
    shared_secret:   bytes
    associated_data: bytes

K = TypeVar("K", bound="KeyPair")
class KeyPair(NamedTuple):
    priv: bytes
    pub:  bytes

    def serialize(self) -> KeyPairSerialized:
        return {
            "priv": base64.b64encode(self.priv).decode("ASCII"),
            "pub":  base64.b64encode(self.pub).decode("ASCII")
        }

    @classmethod
    def deserialize(cls: Type[K], serialized: JSONType) -> K:
        assert isinstance(serialized, dict)
        assert "priv" in serialized
        assert "pub"  in serialized
        assert isinstance(serialized["priv"], str)
        assert isinstance(serialized["pub"],  str)

        return cls(
            priv = base64.b64decode(serialized["priv"].encode("ASCII")),
            pub  = base64.b64decode(serialized["pub"].encode("ASCII"))
        )

P = TypeVar("P", bound="SignedPreKeyPair")
class SignedPreKeyPair(NamedTuple):
    key: KeyPair
    sig: bytes
    timestamp: int

    def serialize(self) -> SignedPreKeyPairSerialized:
        return {
            "key": self.key.serialize(),
            "sig": base64.b64encode(self.sig).decode("ASCII"),
            "timestamp": self.timestamp
        }

    @classmethod
    def deserialize(cls: Type[P], serialized: JSONType) -> P:
        assert isinstance(serialized, dict)
        assert "key" in serialized
        assert "sig" in serialized
        assert "timestamp" in serialized

        assert isinstance(serialized["sig"], str)
        assert isinstance(serialized["timestamp"], int)

        return cls(
            key = KeyPair.deserialize(serialized["key"]),
            sig = base64.b64decode(serialized["sig"].encode("ASCII")),
            timestamp = serialized["timestamp"]
        )

################
# Enumerations #
################

class Curve(Enum):
    Curve448:   str = "Curve448"
    Curve25519: str = "Curve25519"

class CurveType(Enum):
    Mont: str = "Mont"
    Ed:   str = "Ed"

class HashFunction(Enum):
    SHA_256: str = "SHA-256"
    SHA_512: str = "SHA-512"

##############
# Exceptions #
##############

class InconsistentConfigurationException(Exception):
    pass

class KeyExchangeException(Exception):
    pass
