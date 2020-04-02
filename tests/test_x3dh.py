# pylint: disable=broad-except
# pylint: disable=too-many-nested-blocks
# pylint: disable=too-many-statements

import base64
import json
import os
import random
import time
from typing import Dict, Optional, Any, Union, Type, List, Iterator
from unittest import mock
import warnings

import pytest # type: ignore[import]
import x3dh

# All test coroutines will be treated as marked.
pytestmark = pytest.mark.asyncio

def flip_random_bit(data: bytes, exclude_msb: bool = False) -> bytes:
    # For Curve25519, the most significant bit of the public key is always cleared/ignored, as per RFC 7748
    # (on page 7). Thus, a bit flip of that bit does not make the signature verification fail, because the bit
    # flip is ignored. The `exclude_msb` parameter can be used to disallow the bit flip to appear on the most
    # significant bit and should be set when working with Curve25519 public keys.
    while True:
        modify_byte = random.randrange(len(data))
        modify_bit  = random.randrange(8)

        # If the most significant bit was randomly chosen and `exclude_msb` is set, choose again.
        if not (exclude_msb and modify_byte == len(data) - 1 and modify_bit == 7):
            break

    data_mut = bytearray(data)
    data_mut[modify_byte] ^= 1 << modify_bit
    return bytes(data_mut)

bundles: Dict[bytes, x3dh.Bundle] = {}

class ExampleState(x3dh.State):
    async def _publish_bundle(self, bundle: x3dh.Bundle) -> Any:
        bundles[bundle.ik] = bundle

    def _encode_public_key(self, curve: x3dh.Curve, key_type: x3dh.CurveType, pub: bytes) -> bytes:
        curve_indicator: bytes = curve.value.encode("ASCII")
        key_type_indicator: bytes = key_type.value.encode("ASCII")

        return curve_indicator + b"\x42" + pub + b"\x13\x37" + key_type_indicator

def get_bundle(state: ExampleState) -> x3dh.Bundle:
    if state.ik_mont in bundles:
        return bundles[state.ik_mont]
    if state.ik_ed in bundles:
        return bundles[state.ik_ed]
    assert False

async def create_state(state_settings: Dict[str, Any]) -> ExampleState:
    exc: Optional[BaseException] = None
    state: Optional[ExampleState] = None
    try:
        state = await ExampleState.create(**state_settings)
    except BaseException as e:
        exc = e
    assert exc is None
    assert state is not None
    get_bundle(state)

    return state

async def create_state_expect(
    state_settings: Dict[str, Any],
    expected_exception: Type[BaseException],
    expected_message: Union[str, List[str]]
) -> None:
    exc: Optional[BaseException] = None
    state: Optional[ExampleState] = None
    try:
        state = await ExampleState.create(**state_settings)
    except BaseException as e:
        exc = e
    assert state is None

    assert isinstance(exc, expected_exception)
    if not isinstance(expected_message, list):
        expected_message = [ expected_message ]
    for expected_message_snippet in expected_message:
        assert expected_message_snippet in str(exc)

def generate_settings(
    info_string: str,
    spk_timeout: int = 7,
    opk_refill_threshold: int = 25,
    opk_refill_target: int = 100,
    all_possibilities: bool = False
) -> Iterator[Dict[str, Any]]:
    for curve in [ x3dh.Curve.Curve448, x3dh.Curve.Curve25519 ]:
        for internal_ik_type in [ x3dh.CurveType.Mont, x3dh.CurveType.Ed ]:
            for external_ik_type in [ x3dh.CurveType.Mont, x3dh.CurveType.Ed ]:
                for hash_function in [ x3dh.HashFunction.SHA_256, x3dh.HashFunction.SHA_512 ]:
                    state_settings: Dict[str, Any] = {
                        "curve": curve,
                        "internal_ik_type": internal_ik_type,
                        "external_ik_type": external_ik_type,
                        "hash_function": hash_function,
                        "info_string": info_string,
                        "spk_timeout": spk_timeout,
                        "opk_refill_threshold": opk_refill_threshold,
                        "opk_refill_target": opk_refill_target
                    }

                    if not all_possibilities:
                        if internal_ik_type is x3dh.CurveType.Ed and external_ik_type is x3dh.CurveType.Mont:
                            # This combination of internal and external identity key types is forbidden.
                            continue

                        if curve is x3dh.Curve.Curve448:
                            # Curve448 is currently not supported.
                            continue

                    yield state_settings

async def test_key_agreements() -> None:
    for state_settings in generate_settings("test_key_agreements"):
        state_a = await create_state(state_settings)
        state_b = await create_state(state_settings)

        # Store the current bundles
        bundle_a_before = get_bundle(state_a)
        bundle_b_before = get_bundle(state_b)

        # Perform the first, active half of the key agreement
        shared_secret_active = await state_a.get_shared_secret_active(
            bundle_b_before,
            "ad appendix".encode("ASCII")
        )

        # Perform the second, passive half of the key agreement
        shared_secret_passive = await state_b.get_shared_secret_passive(
            shared_secret_active.header,
            "ad appendix".encode("ASCII")
        )

        # Store the current bundles
        bundle_a_after = get_bundle(state_a)
        bundle_b_after = get_bundle(state_b)

        # The bundle of the active party should remain unmodified:
        assert bundle_a_after == bundle_a_before

        # The bundle of the passive party should have been modified and published again:
        assert bundle_b_after != bundle_b_before

        # To be exact, only one one-time pre key should have been removed from the bundle:
        assert bundle_b_after.ik        == bundle_b_before.ik
        assert bundle_b_after.spk       == bundle_b_before.spk
        assert bundle_b_after.spk_sig   == bundle_b_before.spk_sig
        assert len(bundle_b_after.opks) == len(bundle_b_before.opks) - 1
        assert all(opk in bundle_b_before.opks for opk in bundle_b_after.opks)

        # Both parties should have derived the same shared secret and built the same
        # associated data:
        assert shared_secret_active.shared_secret   == shared_secret_passive.shared_secret
        assert shared_secret_active.associated_data == shared_secret_passive.associated_data

        # It should not be possible to accept the same header again:
        try:
            await state_b.get_shared_secret_passive(
                shared_secret_active.header,
                "ad appendix".encode("ASCII")
            )
            assert False
        except x3dh.KeyExchangeException as e:
            assert "one-time pre key" in str(e)
            assert "not available"    in str(e)

        # If the key agreement does not use a one-time pre key, it should be possible to accept the header
        # multiple times:
        bundle_b = get_bundle(state_b)
        bundle_b = x3dh.Bundle(ik=bundle_b.ik, spk=bundle_b.spk, spk_sig=bundle_b.spk_sig, opks=[])

        shared_secret_active = await state_a.get_shared_secret_active(bundle_b, require_opk=False)

        shared_secret_passive = await state_b.get_shared_secret_passive(
            shared_secret_active.header,
            require_opk=False
        )
        assert shared_secret_active.shared_secret   == shared_secret_passive.shared_secret
        assert shared_secret_active.associated_data == shared_secret_passive.associated_data

        shared_secret_passive = await state_b.get_shared_secret_passive(
            shared_secret_active.header,
            require_opk=False
        )
        assert shared_secret_active.shared_secret   == shared_secret_passive.shared_secret
        assert shared_secret_active.associated_data == shared_secret_passive.associated_data

async def test_configuration() -> None:
    for state_settings in generate_settings("test_configuration", all_possibilities=True):
        curve: x3dh.Curve = state_settings["curve"]
        internal_ik_type: x3dh.CurveType = state_settings["internal_ik_type"]
        external_ik_type: x3dh.CurveType = state_settings["external_ik_type"]

        if internal_ik_type is x3dh.CurveType.Ed and external_ik_type is x3dh.CurveType.Mont:
            # This combination of internal and external identity key types is forbidden.
            # The call should throw an exception without publishing the bundle.
            await create_state_expect(state_settings, ValueError, [
                "internal_ik_type",
                "external_ik_type"
            ])
            continue


        if curve is x3dh.Curve.Curve448:
            # Curve448 is currently not supported.
            await create_state_expect(state_settings, NotImplementedError, "Curve448")
            continue

        # Before destorying the settings, make sure that the state could be created like that:
        await create_state(state_settings)

        # Pass in a non-ASCII info string:
        state_settings["info_string"] = "😁"
        await create_state_expect(state_settings, ValueError, "info_string")
        state_settings["info_string"] = "test_configuration"

        # Pass an invalid timeout for the signed pre key
        state_settings["spk_timeout"] = 0
        await create_state_expect(state_settings, ValueError, "spk_timeout")
        state_settings["spk_timeout"] = -random.randrange(1, 2**64)
        await create_state_expect(state_settings, ValueError, "spk_timeout")
        state_settings["spk_timeout"] = 1

        # Pass an invalid combination of opk_refill_threshold and opk_refill_target
        # opk_refill_threshold too small
        state_settings["opk_refill_threshold"] = 0
        await create_state_expect(state_settings, ValueError, "opk_refill_threshold")
        state_settings["opk_refill_threshold"] = 25

        # opk_refill_target too small
        state_settings["opk_refill_target"] = 0
        await create_state_expect(state_settings, ValueError, "opk_refill_target")
        state_settings["opk_refill_target"] = 100

        # opk_refill_threshold above opk_refill_target
        state_settings["opk_refill_threshold"] = 100
        state_settings["opk_refill_target"] = 25
        await create_state_expect(state_settings, ValueError, [
            "opk_refill_threshold",
            "opk_refill_target"
        ])
        state_settings["opk_refill_threshold"] = 25
        state_settings["opk_refill_target"] = 100

        # opk_refill_threshold equals opk_refill_target (this should succeed)
        state_settings["opk_refill_threshold"] = 25
        state_settings["opk_refill_target"] = 25
        await create_state(state_settings)
        state_settings["opk_refill_threshold"] = 25
        state_settings["opk_refill_target"] = 100

async def test_opk_refill() -> None:
    for state_settings in generate_settings("test_opk_refill", opk_refill_threshold=5, opk_refill_target=10):
        state_a = await create_state(state_settings)
        state_b = await create_state(state_settings)

        # Verify that the bundle contains 100 one-time pre keys initially:
        prev = len(get_bundle(state_b).opks)
        assert prev == state_settings["opk_refill_target"]

        # Perform a lot of key agreements and verify that the refill works as expected:
        for _ in range(100):
            shared_secret_active = await state_a.get_shared_secret_active(get_bundle(state_b))
            await state_b.get_shared_secret_passive(shared_secret_active.header)

            num_opks = len(get_bundle(state_b).opks)

            if prev == state_settings["opk_refill_threshold"]:
                assert num_opks == state_settings["opk_refill_target"]
            else:
                assert num_opks == prev - 1

            prev = num_opks

async def test_spk_signature_verification() -> None:
    for state_settings in generate_settings("test_spk_signature_verification"):
        curve: x3dh.Curve = state_settings["curve"]
        external_ik_type: x3dh.CurveType = state_settings["external_ik_type"]

        for _ in range(100):
            state_a = await create_state(state_settings)
            state_b = await create_state(state_settings)

            bundle = get_bundle(state_b)

            # First, make sure that the active half of the key agreement usually works:
            await state_a.get_shared_secret_active(bundle)

            # Now, flip a random bit in
            # 1. the signature
            # 2. the identity key
            # 3. the signed pre key
            # and make sure that the active half of the key agreement reject the signature.

            # 1.: the signature
            spk_sig = flip_random_bit(bundle.spk_sig)
            bundle_modified = x3dh.Bundle(ik=bundle.ik, spk=bundle.spk, spk_sig=spk_sig, opks=bundle.opks)
            try:
                await state_a.get_shared_secret_active(bundle_modified)
                assert False
            except x3dh.KeyExchangeException as e:
                assert "signature" in str(e)

            # 2.: the identity key
            exclude_msb = curve is x3dh.Curve.Curve25519 and external_ik_type is x3dh.CurveType.Mont
            ik = flip_random_bit(bundle.ik, exclude_msb=exclude_msb)
            bundle_modified = x3dh.Bundle(ik=ik, spk=bundle.spk, spk_sig=bundle.spk_sig, opks=bundle.opks)
            try:
                await state_a.get_shared_secret_active(bundle_modified)
                assert False
            except x3dh.KeyExchangeException as e:
                assert "signature" in str(e)

            # 3.: the signed pre key
            spk = flip_random_bit(bundle.spk)
            bundle_modified = x3dh.Bundle(ik=bundle.ik, spk=spk, spk_sig=bundle.spk_sig, opks=bundle.opks)
            try:
                await state_a.get_shared_secret_active(bundle_modified)
                assert False
            except x3dh.KeyExchangeException as e:
                assert "signature" in str(e)

async def test_opk_availability() -> None:
    for state_settings in generate_settings("test_opk_availability"):
        state_a = await create_state(state_settings)
        state_b = await create_state(state_settings)

        # First, test the active half of the key agreement
        for require_opk in [ True, False ]:
            for include_opk in [ True, False ]:
                bundle = get_bundle(state_b)

                # Make sure that the bundle contains one-time pre keys:
                assert len(bundle.opks) > 0

                # If required for the test, remove all one-time pre keys:
                if not include_opk:
                    bundle = x3dh.Bundle(ik=bundle.ik, spk=bundle.spk, spk_sig=bundle.spk_sig, opks=[])

                should_fail = require_opk and not include_opk
                try:
                    shared_secret_active = await state_a.get_shared_secret_active(
                        bundle,
                        require_opk=require_opk
                    )
                    assert not should_fail
                    assert (shared_secret_active.header.opk is not None) == include_opk
                except x3dh.KeyExchangeException as e:
                    assert should_fail
                    assert "does not contain" in str(e)
                    assert "one-time pre key" in str(e)

        # Second, test the passive half of the key agreement
        for require_opk in [ True, False ]:
            for include_opk in [ True, False ]:
                bundle = get_bundle(state_b)

                # Make sure that the bundle contains one-time pre keys:
                assert len(bundle.opks) > 0

                # If required for the test, remove all one-time pre keys:
                if not include_opk:
                    bundle = x3dh.Bundle(ik=bundle.ik, spk=bundle.spk, spk_sig=bundle.spk_sig, opks=[])

                # Perform the active half of the key agreement, using a one-time pre key only if required for
                # the test.
                shared_secret_active = await state_a.get_shared_secret_active(bundle, require_opk=False)

                should_fail = require_opk and not include_opk
                try:
                    shared_secret_passive = await state_b.get_shared_secret_passive(
                        shared_secret_active.header,
                        require_opk=require_opk
                    )
                    assert not should_fail
                    assert shared_secret_passive.shared_secret == shared_secret_active.shared_secret
                except x3dh.KeyExchangeException as e:
                    assert should_fail
                    assert "does not use" in str(e)
                    assert "one-time pre key" in str(e)

THREE_DAYS = 3 * 24 * 60 * 60
EIGHT_DAYS = 8 * 24 * 60 * 60

async def test_spk_rotation() -> None:
    for state_settings in generate_settings("test_spk_rotation"):
        state_b  = await create_state(state_settings)
        bundle_b = get_bundle(state_b)

        current_time = time.time()
        time_mock    = mock.MagicMock()

        # Mock time.time, so that the test can skip days in an instant
        with mock.patch("time.time", time_mock):
            # ExampleState.create should call time.time only once, when generating the signed pre key. Make
            # the mock return the actual current time for that call.
            time_mock.return_value = current_time
            state_a = await create_state(state_settings)
            assert time_mock.call_count == 1
            time_mock.reset_mock()

            # Prepare a key agreement header, the time is irrelevant here. Don't use a one-time pre key so
            # that the header can be used multiple times.
            bundle_a = get_bundle(state_a)
            bundle_a = x3dh.Bundle(ik=bundle_a.ik, spk=bundle_a.spk, spk_sig=bundle_a.spk_sig, opks=[])

            time_mock.return_value = current_time + THREE_DAYS
            shared_secret_b = await state_b.get_shared_secret_active(bundle_a, require_opk=False)
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
            assert time_mock.call_count == 1
            time_mock.reset_mock()
            assert get_bundle(state_a) == bundle_a_before

            # Make the mock return the actual current time plus eight days. This should trigger a rotation.
            # A rotation reads the time twice.
            bundle_a_before = get_bundle(state_a)
            time_mock.return_value = current_time + EIGHT_DAYS
            await state_a.get_shared_secret_active(bundle_b)
            assert time_mock.call_count == 2
            time_mock.reset_mock()
            assert get_bundle(state_a).ik      == bundle_a_before.ik
            assert get_bundle(state_a).spk     != bundle_a_before.spk
            assert get_bundle(state_a).spk_sig != bundle_a_before.spk_sig
            assert get_bundle(state_a).opks    == bundle_a_before.opks

            # Update the "current_time" to the creation time of the last signed pre key:
            current_time += EIGHT_DAYS

            # 2. get_shared_secret_passive

            # Make the mock return the actual current time plus three days. This should not trigger a
            # rotation.
            bundle_a_before = get_bundle(state_a)
            time_mock.return_value = current_time + THREE_DAYS
            await state_a.get_shared_secret_passive(shared_secret_b.header, require_opk=False)
            assert time_mock.call_count == 1
            time_mock.reset_mock()
            assert get_bundle(state_a) == bundle_a_before

            # Make the mock return the actual current time plus eight days. This should trigger a rotation.
            # A rotation reads the time twice.
            bundle_a_before = get_bundle(state_a)
            time_mock.return_value = current_time + EIGHT_DAYS
            await state_a.get_shared_secret_passive(shared_secret_b.header, require_opk=False)
            assert time_mock.call_count == 2
            time_mock.reset_mock()
            assert get_bundle(state_a).ik      == bundle_a_before.ik
            assert get_bundle(state_a).spk     != bundle_a_before.spk
            assert get_bundle(state_a).spk_sig != bundle_a_before.spk_sig
            assert get_bundle(state_a).opks    == bundle_a_before.opks

            # Update the "current_time" to the creation time of the last signed pre key:
            current_time += EIGHT_DAYS

            # 3. deserialize

            # Make the mock return the actual current time plus three days. This should not trigger a
            # rotation.
            bundle_a_before = get_bundle(state_a)
            time_mock.return_value = current_time + THREE_DAYS
            state_a = await ExampleState.deserialize(state_a.serialize(), **state_settings)
            assert time_mock.call_count == 1
            time_mock.reset_mock()
            assert get_bundle(state_a) == bundle_a_before

            # Make the mock return the actual current time plus eight days. This should trigger a rotation.
            # A rotation reads the time twice.
            bundle_a_before = get_bundle(state_a)
            time_mock.return_value = current_time + EIGHT_DAYS
            state_a = await ExampleState.deserialize(state_a.serialize(), **state_settings)
            assert time_mock.call_count == 2
            time_mock.reset_mock()
            assert get_bundle(state_a).ik      == bundle_a_before.ik
            assert get_bundle(state_a).spk     != bundle_a_before.spk
            assert get_bundle(state_a).spk_sig != bundle_a_before.spk_sig
            assert get_bundle(state_a).opks    == bundle_a_before.opks

            # Update the "current_time" to the creation time of the last signed pre key:
            current_time += EIGHT_DAYS

async def test_old_spk() -> None:
    for state_settings in generate_settings("test_old_spk", spk_timeout=2):
        state_a = await create_state(state_settings)
        state_b = await create_state(state_settings)

        # Prepare a key agreement header using the current signed pre key of state a. Don't use a one-time pre
        # key so that the header can be used multiple times.
        bundle_a = get_bundle(state_a)
        bundle_a_no_opks = x3dh.Bundle(ik=bundle_a.ik, spk=bundle_a.spk, spk_sig=bundle_a.spk_sig, opks=[])
        shared_secret_active = await state_b.get_shared_secret_active(bundle_a_no_opks, require_opk=False)
        header = shared_secret_active.header

        # Make sure that this key agreement works as intended:
        shared_secret_passive = await state_a.get_shared_secret_passive(header, require_opk=False)
        assert shared_secret_active.shared_secret   == shared_secret_passive.shared_secret
        assert shared_secret_active.associated_data == shared_secret_passive.associated_data

        # Rotate the signed pre key once. The rotation period is specified as two days, still skipping eight
        # days should only trigger a single rotation.
        current_time = time.time()
        time_mock    = mock.MagicMock()

        # Mock time.time, so that the test can skip days in an instant
        with mock.patch("time.time", time_mock):
            time_mock.return_value = current_time + EIGHT_DAYS
            state_a = await ExampleState.deserialize(state_a.serialize(), **state_settings)
            assert time_mock.call_count == 2
            time_mock.reset_mock()

        # Make sure that the signed pre key was rotated:
        assert get_bundle(state_a).ik      == bundle_a.ik
        assert get_bundle(state_a).spk     != bundle_a.spk
        assert get_bundle(state_a).spk_sig != bundle_a.spk_sig
        assert get_bundle(state_a).opks    == bundle_a.opks

        bundle_a_rotated = get_bundle(state_a)

        # The old signed pre key should still be stored in state_a, thus the old key agreement header should
        # still work:
        shared_secret_passive = await state_a.get_shared_secret_passive(header, require_opk=False)
        assert shared_secret_active.shared_secret   == shared_secret_passive.shared_secret
        assert shared_secret_active.associated_data == shared_secret_passive.associated_data

        # Rotate the signed pre key again:
        with mock.patch("time.time", time_mock):
            time_mock.return_value = current_time + EIGHT_DAYS + THREE_DAYS
            state_a = await ExampleState.deserialize(state_a.serialize(), **state_settings)
            assert time_mock.call_count == 2
            time_mock.reset_mock()

        # Make sure that the signed pre key was rotated again:
        assert get_bundle(state_a).ik      == bundle_a.ik
        assert get_bundle(state_a).spk     != bundle_a.spk
        assert get_bundle(state_a).spk_sig != bundle_a.spk_sig
        assert get_bundle(state_a).opks    == bundle_a.opks
        assert get_bundle(state_a).ik      == bundle_a_rotated.ik
        assert get_bundle(state_a).spk     != bundle_a_rotated.spk
        assert get_bundle(state_a).spk_sig != bundle_a_rotated.spk_sig
        assert get_bundle(state_a).opks    == bundle_a_rotated.opks

        # Now the signed pre key used in the header should not be available any more, the passive half of the
        # key agreement should fail:
        try:
            await state_a.get_shared_secret_passive(header, require_opk=False)
            assert False
        except x3dh.KeyExchangeException as e:
            assert "signed pre key" in str(e)
            assert "not available"  in str(e)

async def test_serialization() -> None:
    for state_settings in generate_settings("test_serialization"):
        state_a = await create_state(state_settings)
        state_b = await create_state(state_settings)

        # Make sure that the key agreement works normally:
        shared_secret_active  = await state_a.get_shared_secret_active(get_bundle(state_b))
        shared_secret_passive = await state_b.get_shared_secret_passive(shared_secret_active.header)
        assert shared_secret_active.shared_secret   == shared_secret_passive.shared_secret
        assert shared_secret_active.associated_data == shared_secret_passive.associated_data

        # Do the same thing but serialize and deserialize state b before performing the passive half of the
        # key agreement:
        bundle_b_before = get_bundle(state_b)

        shared_secret_active = await state_a.get_shared_secret_active(get_bundle(state_b))
        state_b = await ExampleState.deserialize(state_b.serialize(), **state_settings)
        shared_secret_passive = await state_b.get_shared_secret_passive(shared_secret_active.header)
        assert shared_secret_active.shared_secret   == shared_secret_passive.shared_secret
        assert shared_secret_active.associated_data == shared_secret_passive.associated_data

        # Make sure that the bundle remained the same, except for one one-time pre key being deleted:
        assert get_bundle(state_b).ik        == bundle_b_before.ik
        assert get_bundle(state_b).spk       == bundle_b_before.spk
        assert get_bundle(state_b).spk_sig   == bundle_b_before.spk_sig
        assert len(get_bundle(state_b).opks) == len(bundle_b_before.opks) - 1
        assert all(opk in bundle_b_before.opks for opk in get_bundle(state_b).opks)

        # Accepting a key agreement using a one-time pre key results in the one-time pre key being deleted
        # from the state. Use (de)serialization to circumvent the deletion of the one-time pre key. This time
        # also serialize the structure into JSON:
        shared_secret_active = await state_a.get_shared_secret_active(get_bundle(state_b))
        state_b_serialized = json.dumps(state_b.serialize())

        # Accepting the header should work once...
        shared_secret_passive = await state_b.get_shared_secret_passive(shared_secret_active.header)
        assert shared_secret_active.shared_secret   == shared_secret_passive.shared_secret
        assert shared_secret_active.associated_data == shared_secret_passive.associated_data

        # ...but fail the second time:
        try:
            await state_b.get_shared_secret_passive(shared_secret_active.header)
            assert False
        except x3dh.KeyExchangeException as e:
            assert "one-time pre key" in str(e)
            assert "not available"    in str(e)

        # After restoring the state, it should work again:
        state_b = await ExampleState.deserialize(json.loads(state_b_serialized), **state_settings)
        shared_secret_passive = await state_b.get_shared_secret_passive(shared_secret_active.header)
        assert shared_secret_active.shared_secret   == shared_secret_passive.shared_secret
        assert shared_secret_active.associated_data == shared_secret_passive.associated_data

async def test_serialization_consistency_checks() -> None:
    # When deserializing, the code checks whether the settings/configuration has changed and generates
    # warnings/errors accordingly.

    state_settings: Dict[str, Any] = {
        "curve": x3dh.Curve.Curve25519,
        "internal_ik_type": x3dh.CurveType.Mont,
        "external_ik_type": x3dh.CurveType.Ed,
        "hash_function": x3dh.HashFunction.SHA_256,
        "info_string": "test_serialization_consistency_checks",
        "spk_timeout": 7,
        "opk_refill_threshold": 25,
        "opk_refill_target": 100
    }

    state = await create_state(state_settings)

    # Serialize state a with the current settings
    state_serialized = state.serialize()

    # Make sure that the serialization generally works:
    await ExampleState.deserialize(state_serialized, **state_settings)

    # Modify the "curve" setting and verify that `deserialize` throws an exception:
    state_settings["curve"] = x3dh.Curve.Curve448
    try:
        await ExampleState.deserialize(state_serialized, **state_settings)
        assert False
    except x3dh.InconsistentConfigurationException as e:
        assert "uses keys on" in str(e)
    state_settings["curve"] = x3dh.Curve.Curve25519

    # Modify the "internal_ik_type" setting and verify that `deserialize` throws an exception:
    state_settings["internal_ik_type"] = x3dh.CurveType.Ed
    try:
        await ExampleState.deserialize(state_serialized, **state_settings)
        assert False
    except x3dh.InconsistentConfigurationException as e:
        assert "internal" in str(e)
        assert "identity key" in str(e)
    state_settings["internal_ik_type"] = x3dh.CurveType.Mont

    # Modify the "external_ik_type" setting and verify that `deserialize` generates a warning:
    state_settings["external_ik_type"] = x3dh.CurveType.Mont
    with warnings.catch_warnings(record=True) as w:
        await ExampleState.deserialize(state_serialized, **state_settings)
        assert len(w) == 1
        assert issubclass(w[0].category, UserWarning)
        assert "external" in str(w[0].message)
        assert "identity key" in str(w[0].message)
    state_settings["external_ik_type"] = x3dh.CurveType.Ed

    # Modify the "hash_function" setting and verify that `deserialize` generates a warning:
    state_settings["hash_function"] = x3dh.HashFunction.SHA_512
    with warnings.catch_warnings(record=True) as w:
        await ExampleState.deserialize(state_serialized, **state_settings)
        assert len(w) == 1
        assert issubclass(w[0].category, UserWarning)
        assert "hash function" in str(w[0].message)
    state_settings["hash_function"] = x3dh.HashFunction.SHA_256

    # Modify the "info_string" setting and verify that `deserialize` generates a warning:
    state_settings["info_string"] = "something different than before"
    with warnings.catch_warnings(record=True) as w:
        await ExampleState.deserialize(state_serialized, **state_settings)
        assert len(w) == 1
        assert issubclass(w[0].category, UserWarning)
        assert "info string" in str(w[0].message)
    state_settings["info_string"] = "test_serialization_consistency_checks"

    # Finally a sanity check: verify that all settings were restored and the deserialization works again:
    await ExampleState.deserialize(state_serialized, **state_settings)

THIS_FILE_PATH = os.path.dirname(os.path.abspath(__file__))

async def test_migrations() -> None:
    # Test the migration from pre-stable
    state_settings: Dict[str, Any] = {
        "curve": x3dh.Curve.Curve25519,
        "internal_ik_type": x3dh.CurveType.Mont,
        "external_ik_type": x3dh.CurveType.Mont,
        "hash_function": x3dh.HashFunction.SHA_256,
        "info_string": "test_migrations",
        "spk_timeout": 7,
        "opk_refill_threshold": 25,
        "opk_refill_target": 100
    }

    with open(os.path.join(THIS_FILE_PATH, "migration_data", "state-alice-pre-stable.json"), "r") as f:
        state_a_serialized = json.load(f)

    with open(os.path.join(THIS_FILE_PATH, "migration_data", "state-bob-pre-stable.json"), "r") as f:
        state_b_serialized = json.load(f)

    with open(os.path.join(THIS_FILE_PATH, "migration_data", "shared-secret-pre-stable.json"), "r") as f:
        shared_secret_active_serialized = json.load(f)

    # Convert the pre-stable shared secret structure into a x3dh.SharedSecretActive
    shared_secret_active = x3dh.SharedSecretActive(
        shared_secret   = base64.b64decode(shared_secret_active_serialized["sk"].encode("ASCII")),
        associated_data = base64.b64decode(shared_secret_active_serialized["ad"].encode("ASCII")),
        header = x3dh.Header(
            ik  = base64.b64decode(shared_secret_active_serialized["to_other"]["ik"].encode("ASCII")),
            ek  = base64.b64decode(shared_secret_active_serialized["to_other"]["ek"].encode("ASCII")),
            spk = base64.b64decode(shared_secret_active_serialized["to_other"]["spk"].encode("ASCII")),
            opk = base64.b64decode(shared_secret_active_serialized["to_other"]["otpk"].encode("ASCII"))
        )
    )

    # Load state a. This should not trigger a publishing of the bundle, as the `changed` flag is not set.
    # A warning will be printed due missing information in the pre-stable serialization format.
    with warnings.catch_warnings(record=True) as w:
        state_a = await ExampleState.deserialize(state_a_serialized, **state_settings)
        assert len(w) == 1
        assert issubclass(w[0].category, UserWarning)
        assert "pre-stable" in str(w[0].message)

    try:
        get_bundle(state_a)
        assert False
    except AssertionError:
        pass

    # Load state b. This should trigger a publishing of the bundle, as the `changed` flag is set.
    # A warning will be printed due missing information in the pre-stable serialization format.
    with warnings.catch_warnings(record=True) as w:
        state_b = await ExampleState.deserialize(state_b_serialized, **state_settings)
        assert len(w) == 1
        assert issubclass(w[0].category, UserWarning)
        assert "pre-stable" in str(w[0].message)

    get_bundle(state_b)

    # Complete the passive half of the key agreement as created by the pre-stable version:
    shared_secret_passive = await state_b.get_shared_secret_passive(shared_secret_active.header)
    assert shared_secret_active.shared_secret   == shared_secret_passive.shared_secret
    assert shared_secret_active.associated_data == shared_secret_passive.associated_data

    # Try another key agreement using the migrated sessions:
    shared_secret_active  = await state_a.get_shared_secret_active(get_bundle(state_b))
    shared_secret_passive = await state_b.get_shared_secret_passive(shared_secret_active.header)
    assert shared_secret_active.shared_secret   == shared_secret_passive.shared_secret
    assert shared_secret_active.associated_data == shared_secret_passive.associated_data
