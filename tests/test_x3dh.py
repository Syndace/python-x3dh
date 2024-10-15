import base64
import json
import os
import random
import time
from typing import Any, Dict, Iterator, List, Optional, Type, Union
from unittest import mock

import x3dh


__all__ = [
    "test_configuration",
    "test_key_agreements",
    "test_migrations",
    "test_old_signed_pre_key",
    "test_pre_key_availability",
    "test_pre_key_refill",
    "test_serialization",
    "test_signed_pre_key_rotation",
    "test_signed_pre_key_signature_verification"
]


try:
    import pytest
except ImportError:
    pass
else:
    pytestmark = pytest.mark.asyncio


def flip_random_bit(data: bytes, exclude_msb: bool = False) -> bytes:
    """
    Flip a random bit in a byte array.

    Args:
        data: The byte array to flip a random bit in.
        exclude_msb: Whether the most significant bit of the byte array should be excluded from the random
            selection. See note below.

    For Curve25519, the most significant bit of the public key is always cleared/ignored, as per RFC 7748 (on
    page 7). Thus, a bit flip of that bit does not make the signature verification fail, because the bit flip
    is ignored. The `exclude_msb` parameter can be used to disallow the bit flip to appear on the most
    significant bit and should be set when working with Curve25519 public keys.

    Returns:
        The data with a random bit flipped.
    """

    while True:
        modify_byte = random.randrange(len(data))
        modify_bit = random.randrange(8)

        # If the most significant bit was randomly chosen and `exclude_msb` is set, choose again.
        if not (exclude_msb and modify_byte == len(data) - 1 and modify_bit == 7):
            break

    data_mut = bytearray(data)
    data_mut[modify_byte] ^= 1 << modify_bit
    return bytes(data_mut)


bundles: Dict[bytes, x3dh.Bundle] = {}


class ExampleState(x3dh.State):
    """
    A state implementation for testing, which simulates bundle uploads by storing them in a global variable,
    and does some fancy public key encoding.
    """

    def _publish_bundle(self, bundle: x3dh.Bundle) -> None:
        bundles[bundle.identity_key] = bundle

    @staticmethod
    def _encode_public_key(key_format: x3dh.IdentityKeyFormat, pub: bytes) -> bytes:
        return b"\x42" + pub + b"\x13\x37" + key_format.value.encode("ASCII")


def get_bundle(state: ExampleState) -> x3dh.Bundle:
    """
    Retrieve a bundle from the simulated server.

    Args:
        state: The state to retrieve the bundle for.

    Returns:
        The bundle.

    Raises:
        AssertionError: if the bundle was never "uploaded".
    """

    if state.bundle.identity_key in bundles:
        return bundles[state.bundle.identity_key]
    assert False


def create_state(state_settings: Dict[str, Any]) -> ExampleState:
    """
    Create an :class:`ExampleState` and make sure the state creation worked as expected.

    Args:
        state_settings: Arguments to pass to :meth:`ExampleState.create`.

    Returns:
        The state.

    Raises:
        AssertionError: in case of failure.
    """

    exc: Optional[BaseException] = None
    state: Optional[ExampleState] = None
    try:
        state = ExampleState.create(**state_settings)
    except BaseException as e:  # pylint: disable=broad-except
        exc = e
    assert exc is None
    assert state is not None
    get_bundle(state)

    return state


def create_state_expect(
    state_settings: Dict[str, Any],
    expected_exception: Type[BaseException],
    expected_message: Union[str, List[str]]
) -> None:
    """
    Create an :class:`ExampleState`, but expect an exception to be raised during creation..

    Args:
        state_settings: Arguments to pass to :meth:`ExampleState.create`.
        expected_exception: The exception type expected to be raised.
        expected_message: The message expected to be raised, or a list of message snippets that should be part
            of the exception message.

    Raises:
        AssertionError: in case of failure.
    """

    exc: Optional[BaseException] = None
    state: Optional[ExampleState] = None
    try:
        state = ExampleState.create(**state_settings)
    except BaseException as e:  # pylint: disable=broad-except
        exc = e
    assert state is None

    assert isinstance(exc, expected_exception)
    if not isinstance(expected_message, list):
        expected_message = [ expected_message ]
    for expected_message_snippet in expected_message:
        assert expected_message_snippet in str(exc)


def generate_settings(
    info: bytes,
    signed_pre_key_rotation_period: int = 7 * 24 * 60 * 60,
    pre_key_refill_threshold: int = 25,
    pre_key_refill_target: int = 100
) -> Iterator[Dict[str, Any]]:
    """
    Generate state creation arguments.

    Args:
        info: The info to use constantly.
        signed_pre_key_rotation_period: The signed pre key rotation period to use constantly.
        pre_key_refill_threshold: The pre key refill threshold to use constantly.
        pre_key_refill_target. The pre key refill target to use constantly.

    Returns:
        An iterator which yields a set of state creation arguments, returning all valid combinations of
        identity key format and hash function with the given constant values.
    """

    for identity_key_format in [ x3dh.IdentityKeyFormat.CURVE_25519, x3dh.IdentityKeyFormat.ED_25519 ]:
        for hash_function in [ x3dh.HashFunction.SHA_256, x3dh.HashFunction.SHA_512 ]:
            state_settings: Dict[str, Any] = {
                "identity_key_format": identity_key_format,
                "hash_function": hash_function,
                "info": info,
                "signed_pre_key_rotation_period": signed_pre_key_rotation_period,
                "pre_key_refill_threshold": pre_key_refill_threshold,
                "pre_key_refill_target": pre_key_refill_target
            }

            yield state_settings


async def test_key_agreements() -> None:
    """
    Test the general key agreement functionality.
    """

    for state_settings in generate_settings("test_key_agreements".encode("ASCII")):
        state_a = create_state(state_settings)
        state_b = create_state(state_settings)

        # Store the current bundles
        bundle_a_before = get_bundle(state_a)
        bundle_b_before = get_bundle(state_b)

        # Perform the first, active half of the key agreement
        shared_secret_active, associated_data_active, header = await state_a.get_shared_secret_active(
            bundle_b_before,
            "ad appendix".encode("ASCII")
        )

        # Perform the second, passive half of the key agreement
        shared_secret_passive, associated_data_passive, _ = await state_b.get_shared_secret_passive(
            header,
            "ad appendix".encode("ASCII")
        )

        # Store the current bundles
        bundle_a_after = get_bundle(state_a)
        bundle_b_after = get_bundle(state_b)

        # The bundle of the active party should remain unmodified:
        assert bundle_a_after == bundle_a_before

        # The bundle of the passive party should have been modified and published again:
        assert bundle_b_after != bundle_b_before

        # To be exact, only one pre key should have been removed from the bundle:
        assert bundle_b_after.identity_key == bundle_b_before.identity_key
        assert bundle_b_after.signed_pre_key == bundle_b_before.signed_pre_key
        assert bundle_b_after.signed_pre_key_sig == bundle_b_before.signed_pre_key_sig
        assert len(bundle_b_after.pre_keys) == len(bundle_b_before.pre_keys) - 1
        assert all(pre_key in bundle_b_before.pre_keys for pre_key in bundle_b_after.pre_keys)

        # Both parties should have derived the same shared secret and built the same
        # associated data:
        assert shared_secret_active == shared_secret_passive
        assert associated_data_active == associated_data_passive

        # It should not be possible to accept the same header again:
        try:
            await state_b.get_shared_secret_passive(
                header,
                "ad appendix".encode("ASCII")
            )
            assert False
        except x3dh.KeyAgreementException as e:
            assert "pre key" in str(e)
            assert "not available" in str(e)

        # If the key agreement does not use a pre key, it should be possible to accept the header
        # multiple times:
        bundle_b = get_bundle(state_b)
        bundle_b = x3dh.Bundle(
            identity_key=bundle_b.identity_key,
            signed_pre_key=bundle_b.signed_pre_key,
            signed_pre_key_sig=bundle_b.signed_pre_key_sig,
            pre_keys=frozenset()
        )

        shared_secret_active, associated_data_active, header = await state_a.get_shared_secret_active(
            bundle_b,
            require_pre_key=False
        )

        shared_secret_passive, associated_data_passive, _ = await state_b.get_shared_secret_passive(
            header,
            require_pre_key=False
        )
        assert shared_secret_active == shared_secret_passive
        assert associated_data_active == associated_data_passive

        shared_secret_passive, associated_data_passive, _ = await state_b.get_shared_secret_passive(
            header,
            require_pre_key=False
        )
        assert shared_secret_active == shared_secret_passive
        assert associated_data_active == associated_data_passive


async def test_configuration() -> None:
    """
    Test whether incorrect argument values are rejected correctly.
    """

    for state_settings in generate_settings("test_configuration".encode("ASCII")):
        # Before destorying the settings, make sure that the state could be created like that:
        create_state(state_settings)

        state_settings["info"] = "test_configuration".encode("ASCII")

        # Pass an invalid timeout for the signed pre key
        state_settings["signed_pre_key_rotation_period"] = 0
        create_state_expect(state_settings, ValueError, "signed_pre_key_rotation_period")
        state_settings["signed_pre_key_rotation_period"] = -random.randrange(1, 2**64)
        create_state_expect(state_settings, ValueError, "signed_pre_key_rotation_period")
        state_settings["signed_pre_key_rotation_period"] = 1

        # Pass an invalid combination of pre_key_refill_threshold and pre_key_refill_target
        # pre_key_refill_threshold too small
        state_settings["pre_key_refill_threshold"] = 0
        create_state_expect(state_settings, ValueError, "pre_key_refill_threshold")
        state_settings["pre_key_refill_threshold"] = 25

        # pre_key_refill_target too small
        state_settings["pre_key_refill_target"] = 0
        create_state_expect(state_settings, ValueError, "pre_key_refill_target")
        state_settings["pre_key_refill_target"] = 100

        # pre_key_refill_threshold above pre_key_refill_target
        state_settings["pre_key_refill_threshold"] = 100
        state_settings["pre_key_refill_target"] = 25
        create_state_expect(state_settings, ValueError, [
            "pre_key_refill_threshold",
            "pre_key_refill_target"
        ])
        state_settings["pre_key_refill_threshold"] = 25
        state_settings["pre_key_refill_target"] = 100

        # pre_key_refill_threshold equals pre_key_refill_target (this should succeed)
        state_settings["pre_key_refill_threshold"] = 25
        state_settings["pre_key_refill_target"] = 25
        create_state(state_settings)
        state_settings["pre_key_refill_threshold"] = 25
        state_settings["pre_key_refill_target"] = 100


async def test_pre_key_refill() -> None:
    """
    Test pre key refill.
    """

    for state_settings in generate_settings(
        "test_pre_key_refill".encode("ASCII"),
        pre_key_refill_threshold=5,
        pre_key_refill_target=10
    ):
        state_a = create_state(state_settings)
        state_b = create_state(state_settings)

        # Verify that the bundle contains 100 pre keys initially:
        prev = len(get_bundle(state_b).pre_keys)
        assert prev == state_settings["pre_key_refill_target"]

        # Perform a lot of key agreements and verify that the refill works as expected:
        for _ in range(100):
            header = (await state_a.get_shared_secret_active(get_bundle(state_b)))[2]
            await state_b.get_shared_secret_passive(header)

            num_pre_keys = len(get_bundle(state_b).pre_keys)

            if prev == state_settings["pre_key_refill_threshold"]:
                assert num_pre_keys == state_settings["pre_key_refill_target"]
            else:
                assert num_pre_keys == prev - 1

            prev = num_pre_keys


async def test_signed_pre_key_signature_verification() -> None:
    """
    Test signature verification of the signed pre key.
    """

    for state_settings in generate_settings("test_signed_pre_key_signature_verification".encode("ASCII")):
        identity_key_format: x3dh.IdentityKeyFormat = state_settings["identity_key_format"]

        for _ in range(8):
            state_a = create_state(state_settings)
            state_b = create_state(state_settings)

            bundle = get_bundle(state_b)

            # First, make sure that the active half of the key agreement usually works:
            await state_a.get_shared_secret_active(bundle)

            # Now, flip a random bit in
            # 1. the signature
            # 2. the identity key
            # 3. the signed pre key
            # and make sure that the active half of the key agreement reject the signature.

            # 1.: the signature
            signed_pre_key_sig = flip_random_bit(bundle.signed_pre_key_sig)
            bundle_modified = x3dh.Bundle(
                identity_key=bundle.identity_key,
                signed_pre_key=bundle.signed_pre_key,
                signed_pre_key_sig=signed_pre_key_sig,
                pre_keys=bundle.pre_keys
            )
            try:
                await state_a.get_shared_secret_active(bundle_modified)
                assert False
            except x3dh.KeyAgreementException as e:
                assert "signature" in str(e)

            # 2.: the identity key
            exclude_msb = identity_key_format is x3dh.IdentityKeyFormat.CURVE_25519
            identity_key = flip_random_bit(bundle.identity_key, exclude_msb=exclude_msb)
            bundle_modified = x3dh.Bundle(
                identity_key=identity_key,
                signed_pre_key=bundle.signed_pre_key,
                signed_pre_key_sig=bundle.signed_pre_key_sig,
                pre_keys=bundle.pre_keys
            )
            try:
                await state_a.get_shared_secret_active(bundle_modified)
                assert False
            except x3dh.KeyAgreementException as e:
                assert "signature" in str(e)

            # 3.: the signed pre key
            signed_pre_key = flip_random_bit(bundle.signed_pre_key)
            bundle_modified = x3dh.Bundle(
                identity_key=bundle.identity_key,
                signed_pre_key=signed_pre_key,
                signed_pre_key_sig=bundle.signed_pre_key_sig,
                pre_keys=bundle.pre_keys
            )
            try:
                await state_a.get_shared_secret_active(bundle_modified)
                assert False
            except x3dh.KeyAgreementException as e:
                assert "signature" in str(e)


async def test_pre_key_availability() -> None:
    """
    Test whether key agreements without pre keys work/are rejected as expected.
    """

    for state_settings in generate_settings("test_pre_key_availability".encode("ASCII")):
        state_a = create_state(state_settings)
        state_b = create_state(state_settings)

        # First, test the active half of the key agreement
        for require_pre_key in [ True, False ]:
            for include_pre_key in [ True, False ]:
                bundle = get_bundle(state_b)

                # Make sure that the bundle contains pre keys:
                assert len(bundle.pre_keys) > 0

                # If required for the test, remove all pre keys:
                if not include_pre_key:
                    bundle = x3dh.Bundle(
                        identity_key=bundle.identity_key,
                        signed_pre_key=bundle.signed_pre_key,
                        signed_pre_key_sig=bundle.signed_pre_key_sig,
                        pre_keys=frozenset()
                    )

                should_fail = require_pre_key and not include_pre_key
                try:
                    header = (await state_a.get_shared_secret_active(
                        bundle,
                        require_pre_key=require_pre_key
                    ))[2]
                    assert not should_fail
                    assert (header.pre_key is not None) == include_pre_key
                except x3dh.KeyAgreementException as e:
                    assert should_fail
                    assert "does not contain" in str(e)
                    assert "pre key" in str(e)

        # Second, test the passive half of the key agreement
        for require_pre_key in [ True, False ]:
            for include_pre_key in [ True, False ]:
                bundle = get_bundle(state_b)

                # Make sure that the bundle contains pre keys:
                assert len(bundle.pre_keys) > 0

                # If required for the test, remove all pre keys:
                if not include_pre_key:
                    bundle = x3dh.Bundle(
                        identity_key=bundle.identity_key,
                        signed_pre_key=bundle.signed_pre_key,
                        signed_pre_key_sig=bundle.signed_pre_key_sig,
                        pre_keys=frozenset()
                    )

                # Perform the active half of the key agreement, using a pre key only if required for
                # the test.
                shared_secret_active, _, header = await state_a.get_shared_secret_active(
                    bundle,
                    require_pre_key=False
                )

                should_fail = require_pre_key and not include_pre_key
                try:
                    shared_secret_passive, _, _ = await state_b.get_shared_secret_passive(
                        header,
                        require_pre_key=require_pre_key
                    )
                    assert not should_fail
                    assert shared_secret_passive == shared_secret_active
                except x3dh.KeyAgreementException as e:
                    assert should_fail
                    assert "does not use" in str(e)
                    assert "pre key" in str(e)


THREE_DAYS = 3 * 24 * 60 * 60
EIGHT_DAYS = 8 * 24 * 60 * 60


async def test_signed_pre_key_rotation() -> None:
    """
    Test signed pre key rotation logic.
    """

    for state_settings in generate_settings("test_signed_pre_key_rotation".encode("ASCII")):
        state_b = create_state(state_settings)
        bundle_b = get_bundle(state_b)

        current_time = time.time()
        time_mock = mock.MagicMock()

        # Mock time.time, so that the test can skip days in an instant
        with mock.patch("time.time", time_mock):
            # ExampleState.create should call time.time only once, when generating the signed pre key. Make
            # the mock return the actual current time for that call.
            time_mock.return_value = current_time
            state_a = create_state(state_settings)
            assert time_mock.call_count == 1
            time_mock.reset_mock()

            # Prepare a key agreement header, the time is irrelevant here. Don't use a pre key so
            # that the header can be used multiple times.
            bundle_a = get_bundle(state_a)
            bundle_a = x3dh.Bundle(
                identity_key=bundle_a.identity_key,
                signed_pre_key=bundle_a.signed_pre_key,
                signed_pre_key_sig=bundle_a.signed_pre_key_sig,
                pre_keys=frozenset()
            )

            time_mock.return_value = current_time + THREE_DAYS
            header_b = (await state_b.get_shared_secret_active(bundle_a, require_pre_key=False))[2]
            state_b.rotate_signed_pre_key()
            assert time_mock.call_count == 1
            time_mock.reset_mock()

            # There are three methods that check whether the signed pre key has to be rotated:
            # 1. get_shared_secret_active
            # 2. get_shared_secret_passive
            # 3. deserialize

            # 1. get_shared_secret_active

            # Make the mock return the actual current time plus three days. This should not trigger a
            # rotation.
            bundle_a_before = get_bundle(state_a)
            time_mock.return_value = current_time + THREE_DAYS
            await state_a.get_shared_secret_active(bundle_b)
            state_a.rotate_signed_pre_key()
            assert time_mock.call_count == 1
            time_mock.reset_mock()
            assert get_bundle(state_a) == bundle_a_before

            # Make the mock return the actual current time plus eight days. This should trigger a rotation.
            # A rotation reads the time twice.
            bundle_a_before = get_bundle(state_a)
            time_mock.return_value = current_time + EIGHT_DAYS
            await state_a.get_shared_secret_active(bundle_b)
            state_a.rotate_signed_pre_key()
            assert time_mock.call_count == 2
            time_mock.reset_mock()
            assert get_bundle(state_a).identity_key == bundle_a_before.identity_key
            assert get_bundle(state_a).signed_pre_key != bundle_a_before.signed_pre_key
            assert get_bundle(state_a).signed_pre_key_sig != bundle_a_before.signed_pre_key_sig
            assert get_bundle(state_a).pre_keys == bundle_a_before.pre_keys

            # Update the "current_time" to the creation time of the last signed pre key:
            current_time += EIGHT_DAYS

            # 2. get_shared_secret_passive

            # Make the mock return the actual current time plus three days. This should not trigger a
            # rotation.
            bundle_a_before = get_bundle(state_a)
            time_mock.return_value = current_time + THREE_DAYS
            await state_a.get_shared_secret_passive(header_b, require_pre_key=False)
            state_a.rotate_signed_pre_key()
            assert time_mock.call_count == 1
            time_mock.reset_mock()
            assert get_bundle(state_a) == bundle_a_before

            # Make the mock return the actual current time plus eight days. This should trigger a rotation.
            # A rotation reads the time twice.
            bundle_a_before = get_bundle(state_a)
            time_mock.return_value = current_time + EIGHT_DAYS
            await state_a.get_shared_secret_passive(header_b, require_pre_key=False)
            state_a.rotate_signed_pre_key()
            assert time_mock.call_count == 2
            time_mock.reset_mock()
            assert get_bundle(state_a).identity_key == bundle_a_before.identity_key
            assert get_bundle(state_a).signed_pre_key != bundle_a_before.signed_pre_key
            assert get_bundle(state_a).signed_pre_key_sig != bundle_a_before.signed_pre_key_sig
            assert get_bundle(state_a).pre_keys == bundle_a_before.pre_keys

            # Update the "current_time" to the creation time of the last signed pre key:
            current_time += EIGHT_DAYS

            # 3. deserialize

            # Make the mock return the actual current time plus three days. This should not trigger a
            # rotation.
            bundle_a_before = get_bundle(state_a)
            time_mock.return_value = current_time + THREE_DAYS
            state_a = ExampleState.from_model(state_a.model, **state_settings)
            assert time_mock.call_count == 1
            time_mock.reset_mock()
            assert get_bundle(state_a) == bundle_a_before

            # Make the mock return the actual current time plus eight days. This should trigger a rotation.
            # A rotation reads the time twice.
            bundle_a_before = get_bundle(state_a)
            time_mock.return_value = current_time + EIGHT_DAYS
            state_a = ExampleState.from_model(state_a.model, **state_settings)
            assert time_mock.call_count == 2
            time_mock.reset_mock()
            assert get_bundle(state_a).identity_key == bundle_a_before.identity_key
            assert get_bundle(state_a).signed_pre_key != bundle_a_before.signed_pre_key
            assert get_bundle(state_a).signed_pre_key_sig != bundle_a_before.signed_pre_key_sig
            assert get_bundle(state_a).pre_keys == bundle_a_before.pre_keys

            # Update the "current_time" to the creation time of the last signed pre key:
            current_time += EIGHT_DAYS


async def test_old_signed_pre_key() -> None:
    """
    Test that the old signed pre key remains available for key agreements for one further rotation period.
    """

    for state_settings in generate_settings(
        "test_old_signed_pre_key".encode("ASCII"),
        signed_pre_key_rotation_period=2
    ):
        print(state_settings)
        state_a = create_state(state_settings)
        state_b = create_state(state_settings)

        # Prepare a key agreement header using the current signed pre key of state a. Don't use a pre
        # key so that the header can be used multiple times.
        bundle_a = get_bundle(state_a)
        bundle_a_no_pre_keys = x3dh.Bundle(
            identity_key=bundle_a.identity_key,
            signed_pre_key=bundle_a.signed_pre_key,
            signed_pre_key_sig=bundle_a.signed_pre_key_sig,
            pre_keys=frozenset()
        )
        shared_secret_active, associated_data_active, header = await state_b.get_shared_secret_active(
            bundle_a_no_pre_keys,
            require_pre_key=False
        )

        # Make sure that this key agreement works as intended:
        shared_secret_passive, associated_data_passive, _ = await state_a.get_shared_secret_passive(
            header,
            require_pre_key=False
        )
        assert shared_secret_active == shared_secret_passive
        assert associated_data_active == associated_data_passive

        # Rotate the signed pre key once. The rotation period is specified as two days, still skipping eight
        # days should only trigger a single rotation.
        current_time = time.time()
        time_mock = mock.MagicMock()

        # Mock time.time, so that the test can skip days in an instant
        with mock.patch("time.time", time_mock):
            time_mock.return_value = current_time + EIGHT_DAYS
            state_a = ExampleState.from_model(state_a.model, **state_settings)
            assert time_mock.call_count == 2
            time_mock.reset_mock()

        # Make sure that the signed pre key was rotated:
        assert get_bundle(state_a).identity_key == bundle_a.identity_key
        assert get_bundle(state_a).signed_pre_key != bundle_a.signed_pre_key
        assert get_bundle(state_a).signed_pre_key_sig != bundle_a.signed_pre_key_sig
        assert get_bundle(state_a).pre_keys == bundle_a.pre_keys

        bundle_a_rotated = get_bundle(state_a)

        # The old signed pre key should still be stored in state_a, thus the old key agreement header should
        # still work:
        shared_secret_passive, associated_data_passive, _ = await state_a.get_shared_secret_passive(
            header,
            require_pre_key=False
        )
        assert shared_secret_active == shared_secret_passive
        assert associated_data_active == associated_data_passive

        # Rotate the signed pre key again:
        with mock.patch("time.time", time_mock):
            time_mock.return_value = current_time + EIGHT_DAYS + THREE_DAYS
            state_a = ExampleState.from_model(state_a.model, **state_settings)
            assert time_mock.call_count == 2
            time_mock.reset_mock()

        # Make sure that the signed pre key was rotated again:
        assert get_bundle(state_a).identity_key == bundle_a.identity_key
        assert get_bundle(state_a).signed_pre_key != bundle_a.signed_pre_key
        assert get_bundle(state_a).signed_pre_key_sig != bundle_a.signed_pre_key_sig
        assert get_bundle(state_a).pre_keys == bundle_a.pre_keys
        assert get_bundle(state_a).identity_key == bundle_a_rotated.identity_key
        assert get_bundle(state_a).signed_pre_key != bundle_a_rotated.signed_pre_key
        assert get_bundle(state_a).signed_pre_key_sig != bundle_a_rotated.signed_pre_key_sig
        assert get_bundle(state_a).pre_keys == bundle_a_rotated.pre_keys

        # Now the signed pre key used in the header should not be available any more, the passive half of the
        # key agreement should fail:
        try:
            await state_a.get_shared_secret_passive(header, require_pre_key=False)
            assert False
        except x3dh.KeyAgreementException as e:
            assert "signed pre key" in str(e)
            assert "not available" in str(e)


async def test_serialization() -> None:
    """
    Test (de)serialization.
    """

    for state_settings in generate_settings("test_serialization".encode("ASCII")):
        state_a = create_state(state_settings)
        state_b = create_state(state_settings)

        # Make sure that the key agreement works normally:
        shared_secret_active, associated_data_acitve, header = await state_a.get_shared_secret_active(
            get_bundle(state_b)
        )
        shared_secret_passive, associated_data_passive, _ = await state_b.get_shared_secret_passive(header)
        assert shared_secret_active == shared_secret_passive
        assert associated_data_acitve == associated_data_passive

        # Do the same thing but serialize and deserialize state b before performing the passive half of the
        # key agreement:
        bundle_b_before = get_bundle(state_b)

        shared_secret_active, associated_data_acitve, header = await state_a.get_shared_secret_active(
            get_bundle(state_b)
        )
        state_b = ExampleState.from_model(state_b.model, **state_settings)
        shared_secret_passive, associated_data_passive, _ = await state_b.get_shared_secret_passive(header)
        assert shared_secret_active == shared_secret_passive
        assert associated_data_acitve == associated_data_passive

        # Make sure that the bundle remained the same, except for one pre key being deleted:
        assert get_bundle(state_b).identity_key == bundle_b_before.identity_key
        assert get_bundle(state_b).signed_pre_key == bundle_b_before.signed_pre_key
        assert get_bundle(state_b).signed_pre_key_sig == bundle_b_before.signed_pre_key_sig
        assert len(get_bundle(state_b).pre_keys) == len(bundle_b_before.pre_keys) - 1
        assert all(pre_key in bundle_b_before.pre_keys for pre_key in get_bundle(state_b).pre_keys)

        # Accepting a key agreement using a pre key results in the pre key being deleted
        # from the state. Use (de)serialization to circumvent the deletion of the pre key. This time
        # also serialize the structure into JSON:
        shared_secret_active, associated_data_acitve, header = await state_a.get_shared_secret_active(
            get_bundle(state_b)
        )
        state_b_serialized = json.dumps(state_b.json)

        # Accepting the header should work once...
        shared_secret_passive, associated_data_passive, _ = await state_b.get_shared_secret_passive(header)
        assert shared_secret_active == shared_secret_passive
        assert associated_data_acitve == associated_data_passive

        # ...but fail the second time:
        try:
            await state_b.get_shared_secret_passive(header)
            assert False
        except x3dh.KeyAgreementException as e:
            assert "pre key" in str(e)
            assert "not available" in str(e)

        # After restoring the state, it should work again:
        state_b, needs_publish = ExampleState.from_json(json.loads(state_b_serialized), **state_settings)
        shared_secret_passive, associated_data_passive, _ = await state_b.get_shared_secret_passive(header)
        assert not needs_publish
        assert shared_secret_active == shared_secret_passive
        assert associated_data_acitve == associated_data_passive


THIS_FILE_PATH = os.path.dirname(os.path.abspath(__file__))


async def test_migrations() -> None:
    """
    Test the migration from pre-stable.
    """

    state_settings: Dict[str, Any] = {
        "identity_key_format": x3dh.IdentityKeyFormat.CURVE_25519,
        "hash_function": x3dh.HashFunction.SHA_256,
        "info": "test_migrations".encode("ASCII"),
        "signed_pre_key_rotation_period": 7,
        "pre_key_refill_threshold": 25,
        "pre_key_refill_target": 100
    }

    with open(os.path.join(
        THIS_FILE_PATH,
        "migration_data",
        "state-alice-pre-stable.json"
    ), "r", encoding="utf-8") as state_alice_pre_stable_json:
        state_a_serialized = json.load(state_alice_pre_stable_json)

    with open(os.path.join(
        THIS_FILE_PATH,
        "migration_data",
        "state-bob-pre-stable.json"
    ), "r", encoding="utf-8") as state_bob_pre_stable_json:
        state_b_serialized = json.load(state_bob_pre_stable_json)

    with open(os.path.join(
        THIS_FILE_PATH,
        "migration_data",
        "shared-secret-pre-stable.json"
    ), "r", encoding="utf-8") as shared_secret_pey_stable_json:
        shared_secret_active_serialized = json.load(shared_secret_pey_stable_json)

    # Convert the pre-stable shared secret structure into a x3dh.SharedSecretActive
    shared_secret_active = base64.b64decode(shared_secret_active_serialized["sk"].encode("ASCII"))
    associated_data_active = base64.b64decode(shared_secret_active_serialized["ad"].encode("ASCII"))
    header = x3dh.Header(
        identity_key=base64.b64decode(shared_secret_active_serialized["to_other"]["ik"].encode("ASCII")),
        ephemeral_key=base64.b64decode(shared_secret_active_serialized["to_other"]["ek"].encode("ASCII")),
        signed_pre_key=base64.b64decode(shared_secret_active_serialized["to_other"]["spk"].encode("ASCII")),
        pre_key=base64.b64decode(shared_secret_active_serialized["to_other"]["otpk"].encode("ASCII"))
    )

    # Load state a. This should not trigger a publishing of the bundle, as the `changed` flag is not set.
    state_a, _needs_publish = ExampleState.from_json(state_a_serialized, **state_settings)

    try:
        get_bundle(state_a)
        assert False
    except AssertionError:
        pass

    # Load state b. This should trigger a publishing of the bundle, as the `changed` flag is set.
    state_b, _needs_publish = ExampleState.from_json(state_b_serialized, **state_settings)

    get_bundle(state_b)

    # Complete the passive half of the key agreement as created by the pre-stable version:
    shared_secret_passive, associated_data_passive, _ = await state_b.get_shared_secret_passive(header)
    assert shared_secret_active == shared_secret_passive
    # Don't check the associated data, since formats have changed.

    # Try another key agreement using the migrated sessions:
    shared_secret_active, associated_data_active, header = await state_a.get_shared_secret_active(
        get_bundle(state_b)
    )
    shared_secret_passive, associated_data_passive, _ = await state_b.get_shared_secret_passive(header)
    assert shared_secret_active == shared_secret_passive
    assert associated_data_active == associated_data_passive
