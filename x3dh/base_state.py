# This import from future (theoretically) enables sphinx_autodoc_typehints to handle type aliases better
from __future__ import annotations  # pylint: disable=unused-variable

from abc import ABC, abstractmethod
import json
import time
import secrets
from typing import FrozenSet, Optional, Set, Tuple, Type, TypeVar, cast

import xeddsa

from .crypto_provider import HashFunction
from .crypto_provider_cryptography import CryptoProviderImpl
from .identity_key_pair import IdentityKeyPair, IdentityKeyPairSeed
from .migrations import parse_base_state_model
from .models import BaseStateModel
from .pre_key_pair import PreKeyPair
from .signed_pre_key_pair import SignedPreKeyPair
from .types import Bundle, IdentityKeyFormat, Header, JSONObject


__all__ = [  # pylint: disable=unused-variable
    "KeyAgreementException",
    "BaseState"
]


class KeyAgreementException(Exception):
    """
    Exception raised by :meth:`BaseState.get_shared_secret_active` and
    :meth:`BaseState.get_shared_secret_passive` in case of an error related to the key agreement operation.
    """


BaseStateTypeT = TypeVar("BaseStateTypeT", bound="BaseState")


class BaseState(ABC):
    """
    This class is the core of this X3DH implementation. It offers methods to manually manage the X3DH state
    and perform key agreements with other parties.

    Warning:
        This class requires manual state management, including e.g. signed pre key rotation, pre key
        hiding/deletion and refills. The subclass :class:`~x3dh.state.State` automates those
        management/maintenance tasks and should be preferred if external/manual management is not explicitly
        wanted.
    """

    def __init__(self) -> None:
        # Just the type definitions here
        self.__identity_key_format: IdentityKeyFormat
        self.__hash_function: HashFunction
        self.__info: bytes
        self.__identity_key: IdentityKeyPair
        self.__signed_pre_key: SignedPreKeyPair
        self.__old_signed_pre_key: Optional[SignedPreKeyPair]
        self.__pre_keys: Set[PreKeyPair]
        self.__hidden_pre_keys: Set[PreKeyPair]

    @classmethod
    def create(
        cls: Type[BaseStateTypeT],
        identity_key_format: IdentityKeyFormat,
        hash_function: HashFunction,
        info: bytes,
        identity_key_pair: Optional[IdentityKeyPair] = None
    ) -> BaseStateTypeT:
        """
        Args:
            identity_key_format: The format in which the identity public key is included in bundles/headers.
            hash_function: A 256 or 512-bit hash function.
            info: A (byte) string identifying the application.
            identity_key_pair: If set, use the given identity key pair instead of generating a new one.

        Returns:
            A configured instance of :class:`~x3dh.base_state.BaseState`. Note that an identity key pair and a
            signed pre key are generated, but no pre keys. Use :meth:`generate_pre_keys` to generate some.
        """

        self = cls()
        self.__identity_key_format = identity_key_format
        self.__hash_function = hash_function
        self.__info = info
        self.__identity_key = identity_key_pair or IdentityKeyPairSeed(secrets.token_bytes(32))
        self.__signed_pre_key = self.__generate_spk()
        self.__old_signed_pre_key = None
        self.__pre_keys = set()
        self.__hidden_pre_keys = set()

        return self

    ####################
    # abstract methods #
    ####################

    @staticmethod
    @abstractmethod
    def _encode_public_key(key_format: IdentityKeyFormat, pub: bytes) -> bytes:
        """
        Args:
            key_format: The format in which this public key is serialized.
            pub: The public key.

        Returns:
            An encoding of the public key, possibly including information about the curve and type of key,
            though this is application defined. Note that two different public keys must never result in the
            same byte sequence, uniqueness of the public keys must be preserved.
        """

        raise NotImplementedError("Create a subclass of BaseState and implement `_encode_public_key`.")

    #################
    # serialization #
    #################

    @property
    def model(self) -> BaseStateModel:
        """
        Returns:
            The internal state of this :class:`BaseState` as a pydantic model. Note that pre keys hidden using
            :meth:`hide_pre_key` are not considered part of the state.
        """

        return BaseStateModel(
            identity_key=self.__identity_key.model,
            signed_pre_key=self.__signed_pre_key.model,
            old_signed_pre_key=None if self.__old_signed_pre_key is None else self.__old_signed_pre_key.model,
            pre_keys=frozenset(pre_key.priv for pre_key in self.__pre_keys)
        )

    @property
    def json(self) -> JSONObject:
        """
        Returns:
            The internal state of this :class:`BaseState` as a JSON-serializable Python object. Note that pre
            keys hidden using :meth:`hide_pre_key` are not considered part of the state.
        """

        return cast(JSONObject, json.loads(self.model.model_dump_json()))

    @classmethod
    def from_model(
        cls: Type[BaseStateTypeT],
        model: BaseStateModel,
        identity_key_format: IdentityKeyFormat,
        hash_function: HashFunction,
        info: bytes
    ) -> BaseStateTypeT:
        """
        Args:
            model: The pydantic model holding the internal state of a :class:`BaseState`, as produced by
                :attr:`model`.
            identity_key_format: The format in which the identity public key is included in bundles/headers.
            hash_function: A 256 or 512-bit hash function.
            info: A (byte) string identifying the application.

        Returns:
            A configured instance of :class:`BaseState`, with internal state restored from the model.

        Warning:
            Migrations are not provided via the :attr:`model`/:meth:`from_model` API. Use
            :attr:`json`/:meth:`from_json` instead. Refer to :ref:`serialization_and_migration` in the
            documentation for details.
        """

        self = cls()
        self.__identity_key_format = identity_key_format
        self.__hash_function = hash_function
        self.__info = info
        self.__identity_key = IdentityKeyPair.from_model(model.identity_key)
        self.__signed_pre_key = SignedPreKeyPair.from_model(model.signed_pre_key)
        self.__old_signed_pre_key = (
            None
            if model.old_signed_pre_key is None
            else SignedPreKeyPair.from_model(model.old_signed_pre_key)
        )
        self.__pre_keys = { PreKeyPair(pre_key) for pre_key in model.pre_keys }
        self.__hidden_pre_keys = set()

        return self

    @classmethod
    def from_json(
        cls: Type[BaseStateTypeT],
        serialized: JSONObject,
        identity_key_format: IdentityKeyFormat,
        hash_function: HashFunction,
        info: bytes
    ) -> Tuple[BaseStateTypeT, bool]:
        """
        Args:
            serialized: A JSON-serializable Python object holding the internal state of a :class:`BaseState`,
                as produced by :attr:`json`.
            identity_key_format: The format in which the identity public key is included in bundles/headers.
            hash_function: A 256 or 512-bit hash function.
            info: A (byte) string identifying the application.

        Returns:
            A configured instance of :class:`BaseState`, with internal state restored from the serialized
            data, and a flag that indicates whether the bundle needs to be published. The latter was part of
            the pre-stable serialization format.
        """

        model, bundle_needs_publish = parse_base_state_model(serialized)

        self = cls.from_model(
            model,
            identity_key_format,
            hash_function,
            info
        )

        return self, bundle_needs_publish

    #################################
    # key generation and management #
    #################################

    def __generate_spk(self) -> SignedPreKeyPair:
        """
        Returns:
            A newly generated signed pre key.
        """

        # Get the own identity key in the format required for signing, forcing the sign bit if necessary to
        # comply with XEdDSA
        identity_key = self.__identity_key.as_priv().priv
        if self.__identity_key_format is IdentityKeyFormat.CURVE_25519:
            identity_key = xeddsa.priv_force_sign(identity_key, False)

        # Generate the private key of the new signed pre key
        priv = secrets.token_bytes(32)

        # Sign the encoded public key of the new signed pre key
        sig = xeddsa.ed25519_priv_sign(
            identity_key,
            self._encode_public_key(IdentityKeyFormat.CURVE_25519, xeddsa.priv_to_curve25519_pub(priv))
        )

        # Add the current timestamp
        return SignedPreKeyPair(priv=priv, sig=sig, timestamp=int(time.time()))

    @property
    def old_signed_pre_key(self) -> Optional[bytes]:
        """
        Returns:
            The old signed pre key, if there is one.
        """

        return None if self.__old_signed_pre_key is None else self.__old_signed_pre_key.pub

    def signed_pre_key_age(self) -> int:
        """
        Returns:
            The age of the signed pre key, i.e. the time elapsed since it was last rotated, in seconds.
        """

        return int(time.time()) - self.__signed_pre_key.timestamp

    def rotate_signed_pre_key(self) -> None:
        """
        Rotate the signed pre key. Keep the old signed pre key around for one additional rotation period, i.e.
        until this method is called again.
        """

        self.__old_signed_pre_key = self.__signed_pre_key
        self.__signed_pre_key = self.__generate_spk()

    @property
    def hidden_pre_keys(self) -> FrozenSet[bytes]:
        """
        Returns:
            The currently hidden pre keys.
        """

        return frozenset(pre_key.pub for pre_key in self.__hidden_pre_keys)

    def hide_pre_key(self, pre_key_pub: bytes) -> bool:
        """
        Hide a pre key from the bundle returned by :attr:`bundle` and pre key count returned by
        :meth:`get_num_visible_pre_keys`, but keep the pre key for cryptographic operations. Hidden pre keys
        are not included in the serialized state as returned by :attr:`model` and :attr:`json`.

        Args:
            pre_key_pub: The pre key to hide.

        Returns:
            Whether the pre key was visible before and is hidden now.
        """

        hidden_pre_keys = frozenset(filter(lambda pre_key: pre_key.pub == pre_key_pub, self.__pre_keys))

        self.__pre_keys -= hidden_pre_keys
        self.__hidden_pre_keys |= hidden_pre_keys

        return len(hidden_pre_keys) > 0

    def delete_pre_key(self, pre_key_pub: bytes) -> bool:
        """
        Delete a pre key.

        Args:
            pre_key_pub: The pre key to delete. Can be visible or hidden.

        Returns:
            Whether the pre key existed before and is deleted now.
        """

        deleted_pre_keys = frozenset(filter(
            lambda pre_key: pre_key.pub == pre_key_pub,
            self.__pre_keys | self.__hidden_pre_keys
        ))

        self.__pre_keys -= deleted_pre_keys
        self.__hidden_pre_keys -= deleted_pre_keys

        return len(deleted_pre_keys) > 0

    def delete_hidden_pre_keys(self) -> None:
        """
        Delete all pre keys that were previously hidden using :meth:`hide_pre_key`.
        """

        self.__hidden_pre_keys = set()

    def get_num_visible_pre_keys(self) -> int:
        """
        Returns:
            The number of visible pre keys available. The number returned here matches the number of pre keys
            included in the bundle returned by :attr:`bundle`.
        """

        return len(self.__pre_keys)

    def generate_pre_keys(self, num_pre_keys: int) -> None:
        """
        Generate and store pre keys.

        Args:
            num_pre_keys: The number of pre keys to generate.
        """

        for _ in range(num_pre_keys):
            self.__pre_keys.add(PreKeyPair(priv=secrets.token_bytes(32)))

    @property
    def bundle(self) -> Bundle:
        """
        Returns:
            The bundle, i.e. the public information of this state.
        """

        identity_key = self.__identity_key.as_priv().priv

        return Bundle(
            identity_key=(
                xeddsa.priv_to_curve25519_pub(identity_key)
                if self.__identity_key_format is IdentityKeyFormat.CURVE_25519
                else xeddsa.priv_to_ed25519_pub(identity_key)
            ),
            signed_pre_key=self.__signed_pre_key.pub,
            signed_pre_key_sig=self.__signed_pre_key.sig,
            pre_keys=frozenset(pre_key.pub for pre_key in self.__pre_keys)
        )

    #################
    # key agreement #
    #################

    async def get_shared_secret_active(
        self,
        bundle: Bundle,
        associated_data_appendix: bytes = b"",
        require_pre_key: bool = True
    ) -> Tuple[bytes, bytes, Header]:
        """
        Perform an X3DH key agreement, actively.

        Args:
            bundle: The bundle of the passive party.
            associated_data_appendix: Additional information to append to the associated data, like usernames,
                certificates or other identifying information.
            require_pre_key: Use this flag to abort the key agreement if the bundle does not contain a pre
                key.

        Returns:
            The shared secret and associated data shared between both parties, and the header required by the
            other party to complete the passive part of the key agreement.

        Raises:
            KeyAgreementException: If an error occurs during the key agreement. The exception message will
                contain (human-readable) details.
        """

        # Check whether a pre key is required but not included
        if len(bundle.pre_keys) == 0 and require_pre_key:
            raise KeyAgreementException("This bundle does not contain a pre key.")

        # Get the identity key of the other party in the format required for signature verification
        other_identity_key = bundle.identity_key
        if self.__identity_key_format is IdentityKeyFormat.CURVE_25519:
            other_identity_key = xeddsa.curve25519_pub_to_ed25519_pub(other_identity_key, False)

        # Verify the signature on the signed pre key of the other party
        if not xeddsa.ed25519_verify(
            bundle.signed_pre_key_sig,
            other_identity_key,
            self._encode_public_key(IdentityKeyFormat.CURVE_25519, bundle.signed_pre_key)
        ):
            raise KeyAgreementException("The signature of the signed pre key could not be verified.")

        # All pre-checks successful.

        # Choose a pre key if available
        pre_key = None if len(bundle.pre_keys) == 0 else secrets.choice(list(bundle.pre_keys))

        # Generate the ephemeral key required for the key agreement
        ephemeral_key = secrets.token_bytes(32)

        # Get the own identity key in the format required for X25519
        own_identity_key = self.__identity_key.as_priv().priv

        # Get the identity key of the other party in the format required for X25519
        other_identity_key = bundle.identity_key
        if self.__identity_key_format is IdentityKeyFormat.ED_25519:
            other_identity_key = xeddsa.ed25519_pub_to_curve25519_pub(other_identity_key)

        # Calculate the three to four Diffie-Hellman shared secrets that become the input of HKDF in the next
        # step
        dh1 = xeddsa.x25519(own_identity_key, bundle.signed_pre_key)
        dh2 = xeddsa.x25519(ephemeral_key, other_identity_key)
        dh3 = xeddsa.x25519(ephemeral_key, bundle.signed_pre_key)
        dh4 = b"" if pre_key is None else xeddsa.x25519(ephemeral_key, pre_key)

        # Prepare salt and padding
        salt = b"\x00" * self.__hash_function.hash_size
        padding = b"\xFF" * 32

        # Use HKDF to derive the final shared secret
        shared_secret = await CryptoProviderImpl.hkdf_derive(
            self.__hash_function,
            32,
            salt,
            self.__info,
            padding + dh1 + dh2 + dh3 + dh4
        )

        # Build the associated data for further use by other protocols
        associated_data = (
            self._encode_public_key(self.__identity_key_format, self.bundle.identity_key)
            + self._encode_public_key(self.__identity_key_format, bundle.identity_key)
            + associated_data_appendix
        )

        # Build the header required by the other party to complete the passive part of the key agreement
        header = Header(
            identity_key=self.bundle.identity_key,
            ephemeral_key=xeddsa.priv_to_curve25519_pub(ephemeral_key),
            pre_key=pre_key,
            signed_pre_key=bundle.signed_pre_key
        )

        return shared_secret, associated_data, header

    async def get_shared_secret_passive(
        self,
        header: Header,
        associated_data_appendix: bytes = b"",
        require_pre_key: bool = True
    ) -> Tuple[bytes, bytes, SignedPreKeyPair]:
        """
        Perform an X3DH key agreement, passively.

        Args:
            header: The header received from the active party.
            associated_data_appendix: Additional information to append to the associated data, like usernames,
                certificates or other identifying information.
            require_pre_key: Use this flag to abort the key agreement if the active party did not use a pre
                key.

        Returns:
            The shared secret and the associated data shared between both parties, and the signed pre key pair
            that was used during the key exchange, for use by follow-up protocols.

        Raises:
            KeyAgreementException: If an error occurs during the key agreement. The exception message will
                contain (human-readable) details.
        """

        # Check whether the signed pre key used by this initiation is still available
        signed_pre_key: Optional[SignedPreKeyPair] = None

        if header.signed_pre_key == self.__signed_pre_key.pub:
            # The current signed pre key was used
            signed_pre_key = self.__signed_pre_key

        if self.__old_signed_pre_key is not None and header.signed_pre_key == self.__old_signed_pre_key.pub:
            # The old signed pre key was used
            signed_pre_key = self.__old_signed_pre_key

        if signed_pre_key is None:
            raise KeyAgreementException(
                "This key agreement attempt uses a signed pre key that is not available any more."
            )

        # Check whether a pre key is required but not used
        if header.pre_key is None and require_pre_key:
            raise KeyAgreementException("This key agreement attempt does not use a pre key.")

        # If a pre key was used, check whether it is still available
        pre_key: Optional[bytes] = None
        if header.pre_key is not None:
            pre_key = next((
                pre_key.priv
                for pre_key
                in self.__pre_keys | self.__hidden_pre_keys
                if pre_key.pub == header.pre_key
            ), None)

            if pre_key is None:
                raise KeyAgreementException(
                    "This key agreement attempt uses a pre key that is not available any more."
                )

        # Get the own identity key in the format required for X25519
        own_identity_key = self.__identity_key.as_priv().priv

        # Get the identity key of the other party in the format required for X25519
        other_identity_key = header.identity_key
        if self.__identity_key_format is IdentityKeyFormat.ED_25519:
            other_identity_key = xeddsa.ed25519_pub_to_curve25519_pub(other_identity_key)

        # Calculate the three to four Diffie-Hellman shared secrets that become the input of HKDF in the next
        # step
        dh1 = xeddsa.x25519(signed_pre_key.priv, other_identity_key)
        dh2 = xeddsa.x25519(own_identity_key, header.ephemeral_key)
        dh3 = xeddsa.x25519(signed_pre_key.priv, header.ephemeral_key)
        dh4 = b"" if pre_key is None else xeddsa.x25519(pre_key, header.ephemeral_key)

        # Prepare salt and padding
        salt = b"\x00" * self.__hash_function.hash_size
        padding = b"\xFF" * 32

        # Use HKDF to derive the final shared secret
        shared_secret = await CryptoProviderImpl.hkdf_derive(
            self.__hash_function,
            32,
            salt,
            self.__info,
            padding + dh1 + dh2 + dh3 + dh4
        )

        # Build the associated data for further use by other protocols
        associated_data = (
            self._encode_public_key(self.__identity_key_format, header.identity_key)
            + self._encode_public_key(self.__identity_key_format, self.bundle.identity_key)
            + associated_data_appendix
        )

        return shared_secret, associated_data, signed_pre_key
