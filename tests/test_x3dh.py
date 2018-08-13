from __future__ import division

import json
import time

import x3dh

class ExamplePublicKeyEncoder(x3dh.PublicKeyEncoder):
    @staticmethod
    def encodePublicKey(key, key_type):
        return b"\x42" + key + b"\x13\x37" + key_type.encode("US-ASCII")

class ExampleStateA(x3dh.State):
    def __init__(self):
        super(ExampleStateA, self).__init__(
            info_string = "ThisIsAnExample!".encode("US-ASCII"),
            curve = "25519",
            hash_function = "SHA-256",
            spk_timeout = 7 * 24 * 60 * 60,
            min_num_otpks = 20,
            max_num_otpks = 100,
            public_key_encoder_class = ExamplePublicKeyEncoder
        )

class ExampleStateB(x3dh.State):
    def __init__(self):
        super(ExampleStateB, self).__init__(
            info_string = "ThisIsAnotherExample!".encode("US-ASCII"),
            curve = "25519",
            hash_function = "SHA-512",
            spk_timeout = 2,
            min_num_otpks = 5,
            max_num_otpks = 10,
            public_key_encoder_class = ExamplePublicKeyEncoder
        )

def test_x3dh():
    state_alice = ExampleStateA()
    state_bob   = ExampleStateA()

    previous = 100

    for _ in range(1000):
        bob_bundle = state_bob.getPublicBundle()
        key_exchange_data_active = state_alice.getSharedSecretActive(bob_bundle)

        to_passive = key_exchange_data_active["to_other"]
        key_exchange_data_passive = state_bob.getSharedSecretPassive(to_passive)

        assert state_bob.changed

        if previous == 20:
            assert len(state_bob.getPublicBundle().otpks) == 100
        else:
            assert len(state_bob.getPublicBundle().otpks) == previous - 1

        previous = len(state_bob.getPublicBundle().otpks)

        assert key_exchange_data_active["sk"] == key_exchange_data_passive["sk"]
        assert key_exchange_data_active["ad"] == key_exchange_data_passive["ad"]

def test_spk_rotation():
    state = ExampleStateB()

    spk = state.getPublicBundle().spk

    time.sleep(4)

    assert state.changed
    assert state.getPublicBundle().spk != spk

def test_serialization():
    state_alice = ExampleStateA()
    state_bob   = ExampleStateA()

    previous = 100

    for _ in range(42):
        bob_bundle = state_bob.getPublicBundle()
        key_exchange_data_active = state_alice.getSharedSecretActive(bob_bundle)

        to_passive = key_exchange_data_active["to_other"]
        key_exchange_data_passive = state_bob.getSharedSecretPassive(to_passive)

        assert state_bob.changed

        if previous == 20:
            assert len(state_bob.getPublicBundle().otpks) == 100
        else:
            assert len(state_bob.getPublicBundle().otpks) == previous - 1

        previous = len(state_bob.getPublicBundle().otpks)

        assert key_exchange_data_active["sk"] == key_exchange_data_passive["sk"]
        assert key_exchange_data_active["ad"] == key_exchange_data_passive["ad"]

    state_alice_serialized = json.dumps(state_alice.serialize())
    state_bob_serialized   = json.dumps(state_bob.serialize())

    state_alice = ExampleStateA.fromSerialized(json.loads(state_alice_serialized))
    state_bob   = ExampleStateA.fromSerialized(json.loads(state_bob_serialized))

    for _ in range(42):
        bob_bundle = state_bob.getPublicBundle()
        key_exchange_data_active = state_alice.getSharedSecretActive(bob_bundle)

        to_passive = key_exchange_data_active["to_other"]
        key_exchange_data_passive = state_bob.getSharedSecretPassive(to_passive)

        assert state_bob.changed

        if previous == 20:
            assert len(state_bob.getPublicBundle().otpks) == 100
        else:
            assert len(state_bob.getPublicBundle().otpks) == previous - 1

        previous = len(state_bob.getPublicBundle().otpks)

        assert key_exchange_data_active["sk"] == key_exchange_data_passive["sk"]
        assert key_exchange_data_active["ad"] == key_exchange_data_passive["ad"]
