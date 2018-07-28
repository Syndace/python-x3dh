import time

import x3dh

class ExampleConfigA(x3dh.Config):
    def __init__(self):
        super(ExampleConfigA, self).__init__(
            info_string = "ThisIsAnExample!",
            curve = "25519",
            hash_function = "SHA-256",
            spk_timeout = 7 * 24 * 60 * 60,
            min_num_otpks = 20,
            max_num_otpks = 100
        )

class ExampleConfigB(x3dh.Config):
    def __init__(self):
        super(ExampleConfigB, self).__init__(
            info_string = "ThisIsAnExample!",
            curve = "25519",
            hash_function = "SHA-512",
            spk_timeout = 2,
            min_num_otpks = 5,
            max_num_otpks = 10
        )

class ExampleEncryptionKeyEncoder(x3dh.EncryptionKeyEncoder):
    @staticmethod
    def encodeEncryptionKey(encryption_key, encryption_key_type):
        return b"\x42" + encryption_key + b"\x13\x37"

def test_x3dh():
    state_alice = x3dh.State(ExampleConfigA(), ExampleEncryptionKeyEncoder)
    state_bob   = x3dh.State(ExampleConfigA(), ExampleEncryptionKeyEncoder)

    previous = 100

    for _ in range(1000):
        session_init_data  = state_alice.initSessionActive(state_bob.getPublicBundle())
        other_session_data = state_bob.initSessionPassive(session_init_data["to_other"])

        assert state_bob.changed

        if previous == 20:
            assert len(state_bob.getPublicBundle().otpks) == 100
        else:
            assert len(state_bob.getPublicBundle().otpks) == previous - 1

        previous = len(state_bob.getPublicBundle().otpks)

        assert session_init_data["sk"] == other_session_data["sk"]
        assert session_init_data["ad"] == other_session_data["ad"]

def test_spk_rotation():
    state = x3dh.State(ExampleConfigB(), ExampleEncryptionKeyEncoder)

    spk = state.getPublicBundle().spk

    time.sleep(5)

    assert state.changed
    assert state.getPublicBundle().spk != spk
