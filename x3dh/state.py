import ctypes
import time
import secrets
from typing import TypeVar, Type, Optional, List, Any, Dict
import warnings

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.backends import default_backend
import libnacl
from packaging.version import parse as parse_version
from xeddsa import XEdDSA25519

from .types import (
    # Type Aliases
    JSONType,

    #KeyPairSerialized,
    #SignedPreKeyPairSerialized,
    StateSerialized,

    # Structures (NamedTuples)
    Bundle,
    Header,
    SharedSecretActive,
    SharedSecretPassive,

    KeyPair,
    SignedPreKeyPair,

    # Enumerations
    Curve,
    CurveType,
    HashFunction,

    # Exceptions
    InconsistentConfigurationException,
    KeyExchangeException
)

from .version import __version__

# This is not exported by libnacl (yet), but libnacl ships the required tools to do so.
def crypto_scalarmult(sk: bytes, pk: bytes) -> bytes: # pylint: disable=invalid-name
    if len(pk) != libnacl.crypto_box_PUBLICKEYBYTES:
        raise ValueError('Invalid public key')
    if len(sk) != libnacl.crypto_box_SECRETKEYBYTES:
        raise ValueError('Invalid secret key')
    secret = ctypes.create_string_buffer(libnacl.crypto_scalarmult_BYTES)
    if libnacl.nacl.crypto_scalarmult(secret, sk, pk):
        raise libnacl.CryptError('Failed to compute scalar product')
    return secret.raw

S = TypeVar("S", bound="State")
class State:
    """
    This class is the core of this X3DH implementation. It manages the own :class:`~x3dh.types.Bundle` and
    offers methods to perform key agreements with other parties.
    """

    def __init__(self) -> None:
        # Just the type definitions here
        self.__curve                : Curve
        self.__internal_ik_type     : CurveType
        self.__external_ik_type     : CurveType
        self.__hash_function        : HashFunction
        self.__info_string          : str
        self.__spk_timeout          : int
        self.__opk_refill_threshold : int
        self.__opk_refill_target    : int
        self.__ik                   : KeyPair
        self.__spk                  : SignedPreKeyPair
        self.__old_spk              : Optional[SignedPreKeyPair]
        self.__opks                 : List[KeyPair]

    @classmethod
    def __create(
        cls: Type[S],
        curve: Curve,
        internal_ik_type: CurveType,
        external_ik_type: CurveType,
        hash_function: HashFunction,
        info_string: str,
        spk_timeout: int,
        opk_refill_threshold: int,
        opk_refill_target: int
    ) -> S:
        # pylint: disable=protected-access
        if internal_ik_type is CurveType.Ed and external_ik_type is CurveType.Mont:
            raise ValueError(
                "Invalid value combination passed for the `internal_ik_type` and `external_ik_type`"
                ' parameters. The combination of "Ed" internally and "Mont" externally is forbidden.'
            )

        try:
            info_string.encode("ASCII", errors="strict")
        except UnicodeEncodeError:
            raise ValueError(
                "Invalid value passed for the `info_string` parameter."
                " The string may only contain ASCII-encodable chars."
            )

        if spk_timeout < 1:
            raise ValueError(
                "Invalid value passed for the `spk_timeout` parameter."
                " The signed pre key rotation period must be at least one day."
            )

        if not 1 <= opk_refill_threshold <= opk_refill_target:
            raise ValueError(
                "Invalid value(s) passed for the `opk_refill_threshold` / `opk_refill_target` parameter(s)."
                " `opk_refill_threshold` must be greater than or equal to '1' and lower than or equal to"
                " `opk_refill_target`."
            )

        self = cls()
        self.__curve                = curve
        self.__internal_ik_type     = internal_ik_type
        self.__external_ik_type     = external_ik_type
        self.__hash_function        = hash_function
        self.__info_string          = info_string
        self.__spk_timeout          = spk_timeout
        self.__opk_refill_threshold = opk_refill_threshold
        self.__opk_refill_target    = opk_refill_target

        return self

    @classmethod
    async def create(
        cls: Type[S],
        curve: Curve,
        internal_ik_type: CurveType,
        external_ik_type: CurveType,
        hash_function: HashFunction,
        info_string: str,
        spk_timeout: int,
        opk_refill_threshold: int,
        opk_refill_target: int
    ) -> S:
        # pylint: disable=protected-access
        """
        Args:
            curve: The curve to use for all keys.
            internal_ik_type: The internal type of the identity key pair.
            external_ik_type: The external type of the identity key pair.
            hash_function: A 256 or 512-bit hash function.
            info_string: An ASCII string identifying the application.
            spk_timeout: Rotate the signed pre key after this amount of time in days.
            opk_refill_threshold: Threshold for refilling the one-time pre keys.
            opk_refill_target: When less then `opk_refill_threshold` one-time pre keys are available, generate
                new ones until there are `opk_refill_target` opks again.

        For details regarding the internal and external identity key types, refer to
        :ref:`the documentation <ik-types>`.

        Returns:
            A configured instance of :class:`~x3dh.state.State`.
        """

        self = cls.__create(
            curve,
            internal_ik_type,
            external_ik_type,
            hash_function,
            info_string,
            spk_timeout,
            opk_refill_threshold,
            opk_refill_target
        )

        self.__ik      = self.__generate_ik()
        self.__spk     = self.__generate_spk()
        self.__old_spk = None
        self.__opks    = []

        self.__refill_opks()
        await self.__publish_bundle()

        return self

    ####################
    # abstract methods #
    ####################

    async def _publish_bundle(self, bundle: Bundle) -> Any:
        """
        Args:
            bundle: The bundle to publish, overwriting previously published data.

        Returns:
            Anything, the return value is ignored.

        Note:
            In addition to publishing the bundle, this method can be used as a trigger to persist the state.
            Persisting the state in this method guarantees always remaining up-to-date.

        Note:
            This method is called from :meth:`create`, before :meth:`create` has returned the instance. Thus,
            modifications to the object (``self``, in case of subclasses) may not have happened when this
            method is called.
        """

        raise NotImplementedError("Create a subclass of X3DH and implement `_publish_bundle`.")

    def _encode_public_key(self, curve: Curve, key_type: CurveType, pub: bytes) -> bytes:
        """
        Args:
            curve: The curve this public key belongs to.
            key_type: The type of this public key.
            pub: The public key, encoded as a byte array.

        Returns:
            An encoding of the public key, possibly including information about the curve and type of key,
            though this is application defined. Note that two different public keys must never result in the
            same byte sequence, uniqueness of the public keys must be preserved.
        """

        raise NotImplementedError("Create a subclass of X3DH and implement `_encode_public_key`.")

    #################
    # serialization #
    #################

    def serialize(self) -> StateSerialized:
        """
        Returns:
            The internal state of this instance in a JSON-friendly serializable format. Restore the instance
            using :meth:`deserialize`.
        """

        return {
            "ik": self.__ik.serialize(),
            "spk": self.__spk.serialize(),
            "old_spk": None if self.__old_spk is None else self.__old_spk.serialize(),
            "opks": [ opk.serialize() for opk in self.__opks ],
            "curve": self.__curve.name,
            "internal_ik_type": self.__internal_ik_type.name,
            "external_ik_type": self.__external_ik_type.name,
            "hash_function": self.__hash_function.name,
            "info_string": self.__info_string,
            "version": __version__["short"]
        }

    @classmethod
    async def deserialize(
        cls: Type[S],
        serialized: JSONType,
        curve: Curve,
        internal_ik_type: CurveType,
        external_ik_type: CurveType,
        hash_function: HashFunction,
        info_string: str,
        spk_timeout: int,
        opk_refill_threshold: int,
        opk_refill_target: int
    ) -> S:
        # pylint: disable=protected-access
        # pylint: disable=too-many-statements
        """
        Args:
            serialized: A serialized instance of this class, as produced by :meth:`serialize`.
            curve: The curve to use for all keys.
            internal_ik_type: The internal type of the identity key pair.
            external_ik_type: The external type of the identity key pair.
            hash_function: A 256 or 512-bit hash function.
            info_string: An ASCII string identifying the application.
            spk_timeout: Rotate the signed pre key after this amount of time in days.
            opk_refill_threshold: Threshold for refilling the one-time pre keys.
            opk_refill_target: When less then `opk_refill_threshold` one-time pre keys are available, generate
                new ones until there are `opk_refill_target` opks again.

        For details regarding the internal and external identity key types, refer to
        :ref:`the documentation <ik-types>`.

        Returns:
            A configured instance of :class:`~x3dh.state.State` restored from the serialized data.

        Raises:
            InconsistentConfigurationException: If the state was serialized with a configuration that is
                incompatible with the current configuration.
        """

        publish = False

        def assert_type(obj: Dict[str, Any], key: str, value_type: Any) -> None:
            assert key in obj
            assert isinstance(obj[key], value_type)

        # The only constant between all serialization formats is that the root element is a dictionary.
        assert isinstance(serialized, dict)

        # If the version is included, parse it. Otherwise, assume 0.0.0 for the version.
        version = parse_version("0.0.0")
        if "version" in serialized:
            assert isinstance(serialized["version"], str)
            version = parse_version(serialized["version"])

        # Run migrations
        version_1_0_0 = parse_version("1.0.0")
        if version < version_1_0_0:
            # Migrate pre-stable serialization format
            assert_type(serialized, "changed", bool)
            assert "ik" in serialized
            assert_type(serialized, "spk", dict)
            assert "key" in serialized["spk"]
            assert_type(serialized["spk"], "signature", str)
            assert_type(serialized["spk"], "timestamp", float)
            assert "otpks" in serialized

            publish = serialized["changed"] or publish

            warnings.warn(
                "Importing pre-stable state, the compatibility of the configuration (curve, identity key"
                " types, hash function, info string) can't be confirmed."
            )

            serialized = {
                "ik": serialized["ik"],
                "spk": {
                    "key": serialized["spk"]["key"],
                    "sig": serialized["spk"]["signature"],
                    "timestamp": int(serialized["spk"]["timestamp"])
                },
                "old_spk": None,
                "opks": serialized["otpks"],
                "curve": curve.name,
                "internal_ik_type": internal_ik_type.name,
                "external_ik_type": external_ik_type.name,
                "hash_function": hash_function.name,
                "info_string": info_string,
                "version": "1.0.0"
            }

            version = version_1_0_0

        # All migrations done, deserialize the data.
        assert "ik"      in serialized
        assert "spk"     in serialized
        assert "old_spk" in serialized
        assert_type(serialized, "opks", list)
        assert_type(serialized, "curve", str)
        assert_type(serialized, "internal_ik_type", str)
        assert_type(serialized, "external_ik_type", str)
        assert_type(serialized, "hash_function", str)
        assert_type(serialized, "info_string", str)

        if serialized["curve"] != curve.name:
            raise InconsistentConfigurationException(
                "The serialized state uses keys on {}, the state can't be loaded/converted for {}.".format(
                    serialized["curve"],
                    curve.name
                )
            )

        if serialized["internal_ik_type"] != internal_ik_type.name:
            raise InconsistentConfigurationException(
                "The serialized state uses {} key pairs internally for the identity key, the state can't be"
                " loaded/converted to use {} key pairs instead.".format(
                    serialized["internal_ik_type"],
                    internal_ik_type.name
                )
            )

        if serialized["external_ik_type"] != external_ik_type.name:
            warnings.warn(
                "The external identity key type has changed. This means that all bundles have to be"
                " republished and key agreements initiated prior to this change are now invalid."
            )
            publish = True

        if serialized["hash_function"] != hash_function.name:
            warnings.warn(
                "The hash function has changed. This means that key agreements initiated prior to this change"
                " are now invalid."
            )

        if serialized["info_string"] != info_string:
            warnings.warn(
                "The info string has changed. This means that key agreements initiated prior to this change"
                " are now invalid."
            )

        self = cls.__create(
            curve,
            internal_ik_type,
            external_ik_type,
            hash_function,
            info_string,
            spk_timeout,
            opk_refill_threshold,
            opk_refill_target
        )

        self.__ik      = KeyPair.deserialize(serialized["ik"])
        self.__spk     = SignedPreKeyPair.deserialize(serialized["spk"])
        self.__old_spk = None
        self.__opks    = [ KeyPair.deserialize(opk) for opk in serialized["opks"] ]

        if serialized["old_spk"] is not None:
            self.__old_spk = SignedPreKeyPair.deserialize(serialized["old_spk"])

        publish = self.__refill_opks() or publish
        publish = self.__rotate_spk() or publish
        if publish:
            await self.__publish_bundle()

        return self

    #################################
    # key generation and management #
    #################################

    def __generate_ik(self) -> KeyPair:
        if self.__internal_ik_type is CurveType.Mont:
            return self.__generate_mont_key_pair()

        if self.__internal_ik_type is CurveType.Ed:
            return self.__generate_ed_key_pair()

    def __generate_spk(self) -> SignedPreKeyPair:
        key = self.__generate_mont_key_pair()

        pub_encoded = self._encode_public_key(self.__curve, CurveType.Mont, key.pub)

        sig: bytes

        if self.__curve is Curve.Curve25519:
            if self.__internal_ik_type is CurveType.Mont:
                sig = XEdDSA25519(mont_priv=self.__ik.priv).sign(pub_encoded)

            if self.__internal_ik_type is CurveType.Ed:
                sig = libnacl.crypto_sign_detached(pub_encoded, self.__ik.priv)

        if self.__curve is Curve.Curve448:
            raise NotImplementedError("Sorry, Curve448 is not supported yet.")

        return SignedPreKeyPair(key=key, sig=sig, timestamp=int(time.time()))

    def __rotate_spk(self) -> bool:
        if time.time() - self.__spk.timestamp > self.__spk_timeout * 24 * 60 * 60:
            self.__old_spk = self.__spk
            self.__spk = self.__generate_spk()

            return True

        return False

    def __refill_opks(self) -> bool:
        if len(self.__opks) < self.__opk_refill_threshold:
            while len(self.__opks) < self.__opk_refill_target:
                self.__opks.append(self.__generate_mont_key_pair())

            return True

        return False

    #####################
    # bundle management #
    #####################

    @property
    def __bundle(self) -> Bundle:
        return Bundle(
            ik      = self.__ik_pub_external,
            spk     = self.__spk.key.pub,
            spk_sig = self.__spk.sig,
            opks    = [ opk.pub for opk in self.__opks ]
        )

    async def __publish_bundle(self) -> None:
        await self._publish_bundle(self.__bundle)

    @property
    def ik_mont(self) -> bytes:
        """
        Returns:
            The public part of the identity key, in its Montgomery form.
        """

        return self.__ik_pub_mont

    @property
    def ik_ed(self) -> bytes:
        """
        Returns:
            The public part of the identity key, in its twisted Edwards form.
        """

        return self.__ik_pub_ed

    ####################
    # internal helpers #
    ####################

    def __generate_mont_key_pair(self) -> KeyPair:
        if self.__curve is Curve.Curve25519:
            pub, priv = libnacl.crypto_box_keypair()
            return KeyPair(priv=priv, pub=pub)

        if self.__curve is Curve.Curve448:
            raise NotImplementedError("Sorry, Curve448 is not supported yet.")

    def __generate_ed_key_pair(self) -> KeyPair:
        if self.__curve is Curve.Curve25519:
            pub, priv = libnacl.crypto_sign_keypair()
            return KeyPair(priv=priv, pub=pub)

        if self.__curve is Curve.Curve448:
            raise NotImplementedError("Sorry, Curve448 is not supported yet.")

    @property
    def __ik_priv_mont(self) -> bytes:
        if self.__internal_ik_type is CurveType.Mont:
            return self.__ik.priv

        if self.__internal_ik_type is CurveType.Ed:
            if self.__curve is Curve.Curve25519:
                return libnacl.crypto_sign_ed25519_sk_to_curve25519(self.__ik.priv)

            if self.__curve is Curve.Curve448:
                raise NotImplementedError("Sorry, Curve448 is not supported yet.")

    @property
    def __ik_pub_mont(self) -> bytes:
        return self.__convert_pub(self.__internal_ik_type, CurveType.Mont, self.__ik.pub)

    @property
    def __ik_pub_ed(self) -> bytes:
        return self.__convert_pub(self.__internal_ik_type, CurveType.Ed, self.__ik.pub)

    @property
    def __ik_pub_external(self) -> bytes:
        return self.__convert_pub(self.__internal_ik_type, self.__external_ik_type, self.__ik.pub)

    def __ik_pub_external_to_mont(self, pub: bytes) -> bytes:
        return self.__convert_pub(self.__external_ik_type, CurveType.Mont, pub)

    def __ik_pub_external_to_ed(self, pub: bytes) -> bytes:
        return self.__convert_pub(self.__external_ik_type, CurveType.Ed, pub)

    def __convert_pub(self, from_type: CurveType, to_type: CurveType, pub: bytes) -> bytes:
        if from_type is CurveType.Mont:
            if to_type is CurveType.Mont:
                return pub

            if to_type is CurveType.Ed:
                if self.__curve is Curve.Curve25519:
                    return XEdDSA25519.mont_pub_to_ed_pub(pub)

                if self.__curve is Curve.Curve448:
                    raise NotImplementedError("Sorry, Curve448 is not supported yet.")

        if from_type is CurveType.Ed:
            if to_type is CurveType.Mont:
                if self.__curve is Curve.Curve25519:
                    return libnacl.crypto_sign_ed25519_pk_to_curve25519(pub)

                if self.__curve is Curve.Curve448:
                    raise NotImplementedError("Sorry, Curve448 is not supported yet.")

            if to_type is CurveType.Ed:
                return pub

    def __diffie_hellman(self, priv: bytes, pub: bytes) -> bytes:
        if self.__curve is Curve.Curve25519:
            return crypto_scalarmult(priv, pub)

        if self.__curve is Curve.Curve448:
            raise NotImplementedError("Sorry, Curve448 is not supported yet.")

    def __key_derivation(self, secret_key_material: bytes) -> bytes:
        hash_function: hashes.HashAlgorithm

        if self.__hash_function is HashFunction.SHA_256:
            hash_function = hashes.SHA256()
            salt = b"\x00" * 32
        if self.__hash_function is HashFunction.SHA_512:
            hash_function = hashes.SHA512()
            salt = b"\x00" * 64

        if self.__curve is Curve.Curve25519:
            padding = b"\xFF" * 32
        if self.__curve is Curve.Curve448:
            padding = b"\xFF" * 57

        info = self.__info_string.encode("ASCII", errors="strict")

        return HKDF(
            algorithm=hash_function,
            length=32,
            salt=salt,
            info=info,
            backend=default_backend()
        ).derive(padding + secret_key_material)

    #################
    # key agreement #
    #################

    async def get_shared_secret_active(
        self,
        bundle: Bundle,
        ad_appendix: bytes = b"",
        require_opk: bool = True
    ) -> SharedSecretActive:
        # pylint: disable=invalid-name
        """
        Perform an X3DH key agreement, actively.

        Args:
            bundle: The bundle of the passive party.
            ad_appendix: Additional information to append to the associated data, like usernames, certificates
                or other identifying information.
            require_opk: If set to `True`, the key agreement is aborted if `bundle` does not contain a
                one-time pre key.

        Returns:
            The shared secret and the header required by the passive party to complete their side of the key
            agreement.

        Raises:
            KeyExchangeException: If an error occurs during the key agreement. The exception message will
                contain (human-readable) details.
        """

        if len(bundle.opks) == 0 and require_opk:
            raise KeyExchangeException("This bundle does not contain a one-time pre key.")

        spk_encoded = self._encode_public_key(self.__curve, CurveType.Mont, bundle.spk)

        if self.__curve is Curve.Curve25519:
            try:
                libnacl.crypto_sign_verify_detached(
                    bundle.spk_sig,
                    spk_encoded,
                    self.__ik_pub_external_to_ed(bundle.ik)
                )
            except ValueError:
                raise KeyExchangeException(
                    "The signature of this bundle's signed pre key could not be verified."
                )

        if self.__curve is Curve.Curve448:
            raise NotImplementedError("Sorry, Curve448 is not supported yet.")

        DH  = self.__diffie_hellman
        KDF = self.__key_derivation

        EK = self.__generate_mont_key_pair()

        DH1 = DH(self.__ik_priv_mont, bundle.spk)
        DH2 = DH(EK.priv, self.__ik_pub_external_to_mont(bundle.ik))
        DH3 = DH(EK.priv, bundle.spk)
        DH4 = b""

        opk = None
        if len(bundle.opks) > 0:
            opk = secrets.choice(bundle.opks)

            DH4 = DH(EK.priv, opk)

        SK = KDF(DH1 + DH2 + DH3 + DH4)

        own_ik_external    = self.__ik_pub_external
        active_ik_encoded  = self._encode_public_key(self.__curve, self.__external_ik_type, own_ik_external)
        passive_ik_encoded = self._encode_public_key(self.__curve, self.__external_ik_type, bundle.ik)

        ad = active_ik_encoded + passive_ik_encoded + ad_appendix

        if self.__rotate_spk():
            await self.__publish_bundle()

        return SharedSecretActive(shared_secret=SK, associated_data=ad, header=Header(
            ik  = own_ik_external,
            ek  = EK.pub,
            opk = opk,
            spk = bundle.spk
        ))

    async def get_shared_secret_passive(
        self,
        header: Header,
        ad_appendix: bytes = b"",
        require_opk: bool = True
    ) -> SharedSecretPassive:
        # pylint: disable=invalid-name
        """
        Perform an X3DH key agreement, passively.

        Args:
            header: The header received from the active party.
            ad_appendix: Additional information to append to the associated data, like usernames, certificates
                or other identifying information.
            require_opk: If set to `True`, the key agreement is aborted if the active party did not use a
                one-time pre key.

        Returns:
            The shared secret.

        Raises:
            KeyExchangeException: If an error occurs during the key agreement. The exception message will
                contain (human-readable) details.
        """

        publish = False

        spk = None

        if header.spk == self.__spk.key.pub:
            spk = self.__spk

        if self.__old_spk is not None and header.spk == self.__old_spk.key.pub:
            spk = self.__old_spk

        if spk is None:
            raise KeyExchangeException(
                "This key agreement attempt uses a signed pre key that is not available any more."
            )

        if header.opk is None and require_opk:
            raise KeyExchangeException("This key agreement attempt does not use a one-time pre key.")

        DH  = self.__diffie_hellman
        KDF = self.__key_derivation

        DH1 = DH(spk.key.priv, self.__ik_pub_external_to_mont(header.ik))
        DH2 = DH(self.__ik_priv_mont, header.ek)
        DH3 = DH(spk.key.priv, header.ek)
        DH4 = b""

        if header.opk is not None:
            opks = list(filter(lambda opk: opk.pub == header.opk, self.__opks))
            if len(opks) != 1:
                raise KeyExchangeException(
                    "This key agreement attempt uses a one-time pre key that is not available any more."
                )

            opk = opks[0]

            DH4 = DH(opk.priv, header.ek)

            self.__opks = list(filter(lambda opk: opk.pub != header.opk, self.__opks))
            self.__refill_opks()

            publish = True

        SK = KDF(DH1 + DH2 + DH3 + DH4)

        own_ik_external    = self.__ik_pub_external
        active_ik_encoded  = self._encode_public_key(self.__curve, self.__external_ik_type, header.ik)
        passive_ik_encoded = self._encode_public_key(self.__curve, self.__external_ik_type, own_ik_external)

        ad = active_ik_encoded + passive_ik_encoded + ad_appendix

        publish = self.__rotate_spk() or publish
        if publish:
            await self.__publish_bundle()

        return SharedSecretPassive(shared_secret=SK, associated_data=ad)
