from typing import NamedTuple

import xeddsa


__all__ = [  # pylint: disable=unused-variable
    "PreKeyPair"
]


class PreKeyPair(NamedTuple):
    """
    A pre key.
    """

    priv: bytes

    @property
    def pub(self) -> bytes:
        """
        Returns:
            The public key of this pre key.
        """

        return xeddsa.priv_to_curve25519_pub(self.priv)
