# python-x3dh
#### A python implementation of the Extended Triple Diffie-Hellman key agreement protocol.

This python library offers an implementation of the Extended Triple Diffie-Hellman key agreement protocol (X3DH) as specified [here](https://signal.org/docs/specifications/x3dh/).

Goals for this implementation are:
- Keep it small and simple
- Don't assume any parameters, leave it all configurable
- Keep the structure close to the spec, so readers of the spec have an easy time understanding the code and structure

This library is currently in a very early state, most of the code has not been tested at all, there are probably bugs.

You can find examples in the [OMEMO library](https://github.com/Syndace/python-omemo), which uses this lib.
