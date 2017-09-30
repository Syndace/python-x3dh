# python-x3dh
#### A python implementation of the Extended Triple Diffie-Hellman key agreement protocol.

This python library offers an implementation of the Extended Triple Diffie-Hellman key agreement protocol (X3DH) as specified [here](https://signal.org/docs/specifications/x3dh/).

Goals for this implementation are:
- Keep it small and simple (e.g. don't include the AEAD encryption, leave that to the user of the library)
- Don't assume any parameters, leave it all configurable

This library is currently in a very early state, most of the code has not been tested at all, there are probably bugs.
