from base64 import b64encode, b64decode
import binascii
import enum
import json
from typing import List, NamedTuple, Optional, Dict, Any, TypeVar, Type, Union, Callable

# All TypeVars here to avoid name clashes
A = TypeVar("A")
B = TypeVar("B")
K = TypeVar("K", bound="KeyPair")
P = TypeVar("P", bound="SignedPreKeyPair")

#####################
# Assertion Toolkit #
#####################

class TypeAssertionException(TypeError):
    pass

def assert_in(obj: Dict[Any, Any], key: str) -> Any:
    """
    Asserts that ``obj`` contains an element ``key`` and returns the corresponding element.

    Raises:
        TypeAssertionException: if the object does not contain the expected key.
    """

    if key not in obj:
        raise TypeAssertionException("Dictionary `{}` does not contain key `{}`.".format(obj, key))

    return obj[key]

def assert_type(expected_type: Type[A], obj: Any, key: Optional[str] = None) -> A:
    """
    Args:
        expected_type: The excpected type of ``obj``.
        obj: The object to type check.
        key: If given, the object is treated as a dictionary and ``obj[key]`` is type checked instead of
            ``obj``.

    Returns:
        The type checked and correctly typed object.

    Raises:
        TypeAssertionException: if the object is not of the expected type.
    """

    if key is not None:
        obj = assert_in(assert_type(dict, obj), key)

    if not isinstance(obj, expected_type):
        raise TypeAssertionException("Object `{}` is not of type `{}` but `{}`.".format(
            obj,
            expected_type,
            type(obj)
        ))

    return obj

def assert_type_optional(expected_type: Type[A], obj: Any, key: Optional[str] = None) -> Optional[A]:
    """
    Args:
        expected_type: The excpected type of ``obj``, if ``obj`` is not None.
        obj: The object to type check.
        key: If given, the object is treated as a dictionary and ``obj[key]`` is type checked instead of
            ``obj``.

    Returns:
        The type checked and correctly typed object.

    Raises:
        TypeAssertionException: if the object is not of the expected type.
    """

    if key is not None:
        obj = assert_in(assert_type(dict, obj), key)

    if obj is None:
        return None

    return assert_type(expected_type, obj)

def assert_decode_json(expected_type: Type[A], json_encoded: str) -> A:
    """
    Asserts that ``json_encoded`` contains valid JSON, deserializes the JSON and checks that the resulting
    object has the expected type.

    Raises:
        TypeAssertionException: if the string does not contain valid JSON or the deserialized JSON is not of
            the expected type.
    """

    try:
        return assert_type(expected_type, json.loads(json_encoded))
    except json.JSONDecodeError as e:
        raise TypeAssertionException("The string `{}` does not contain valid JSON.".format(
            json_encoded
        )) from e

def assert_decode_base64(base64_encoded: str) -> bytes:
    """
    Asserts that ``base64_encoded`` is ASCII-encodable and contains valid base64 encoded data, deserializes
    and returns it.

    Raises:
        TypeAssertionException: if the string is not ASCII-encodable or does not contain valid base64 encoded
            data.
    """

    try:
        return b64decode(base64_encoded.encode("ASCII", errors="strict"), validate=True)
    except UnicodeEncodeError as e:
        raise TypeAssertionException("The string `{}` is not ASCII-encodable.".format(
            base64_encoded
        )) from e
    except binascii.Error as e:
        raise TypeAssertionException("The string `{}` does not contain valid base64 encoded data.".format(
            base64_encoded
        )) from e

###########
# Helpers #
###########

def maybe(obj: Optional[A], func: Callable[[A], B]) -> Optional[B]:
    if obj is not None:
        return func(obj)

    return None

def maybe_or(obj: Optional[A], func: Callable[[A], B], exc: BaseException) -> B:
    if obj is not None:
        return func(obj)

    raise exc

def default(obj: Optional[A], value: A) -> A:
    return value if obj is None else obj

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

    ik: bytes
    spk: bytes
    spk_sig: bytes
    opks: List[bytes]

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
    shared_secret: bytes
    associated_data: bytes
    header: Header

class SharedSecretPassive(NamedTuple):
    shared_secret: bytes
    associated_data: bytes

class KeyPair(NamedTuple):
    priv: bytes
    pub: bytes

    def serialize(self) -> KeyPairSerialized:
        return {
            "priv" : b64encode(self.priv).decode("ASCII"),
            "pub"  : b64encode(self.pub).decode("ASCII")
        }

    @classmethod
    def deserialize(cls: Type[K], serialized: JSONType) -> K:
        root = assert_type(dict, serialized)

        return cls(
            priv = assert_decode_base64(assert_type(str, root, "priv")),
            pub  = assert_decode_base64(assert_type(str, root, "pub"))
        )

class SignedPreKeyPair(NamedTuple):
    key: KeyPair
    sig: bytes
    timestamp: int

    def serialize(self) -> SignedPreKeyPairSerialized:
        return {
            "key": self.key.serialize(),
            "sig": b64encode(self.sig).decode("ASCII"),
            "timestamp": self.timestamp
        }

    @classmethod
    def deserialize(cls: Type[P], serialized: JSONType) -> P:
        root = assert_type(dict, serialized)

        return cls(
            key = KeyPair.deserialize(assert_in(root, "key")),
            sig = assert_decode_base64(assert_type(str, root, "sig")),
            timestamp = assert_type(int, root, "timestamp")
        )

################
# Enumerations #
################

@enum.unique
class Curve(enum.Enum):
    Curve448:   str = "Curve448"
    Curve25519: str = "Curve25519"

@enum.unique
class CurveType(enum.Enum):
    Mont: str = "Mont"
    Ed:   str = "Ed"

@enum.unique
class HashFunction(enum.Enum):
    SHA_256: str = "SHA-256"
    SHA_512: str = "SHA-512"

##############
# Exceptions #
##############

class InconsistentConfigurationException(Exception):
    pass

class KeyExchangeException(Exception):
    pass
