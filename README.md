[![PyPI](https://img.shields.io/pypi/v/X3DH.svg)](https://pypi.org/project/X3DH/)
[![PyPI - Python Version](https://img.shields.io/pypi/pyversions/X3DH.svg)](https://pypi.org/project/X3DH/)
[![Build Status](https://travis-ci.org/Syndace/python-x3dh.svg?branch=master)](https://travis-ci.org/Syndace/python-x3dh)
[![Documentation Status](https://readthedocs.org/projects/python-x3dh/badge/?version=latest)](https://python-x3dh.readthedocs.io/en/latest/?badge=latest)

# python-x3dh #

A Python implementation of the [Extended Triple Diffie-Hellman key agreement protocol](https://signal.org/docs/specifications/x3dh/).

## Installation ##

python-x3dh depends on two system libraries, [libxeddsa](https://github.com/Syndace/libxeddsa) and [libsodium](https://download.libsodium.org/doc/).

Install the latest release using pip (`pip install X3DH`) or manually from source by running `pip install .` (preferred) or `python setup.py install` in the cloned repository. The installation requires libsodium and the Python development headers to be installed. If a locally installed version of libxeddsa is available, [python-xeddsa](https://github.com/Syndace/python-xeddsa) (a dependency of python-x3dh) tries to use that. Otherwise it uses prebuilt binaries of the library, which are available for Linux, MacOS and Windows on the amd64 architecture. Set the `LIBXEDDSA_FORCE_LOCAL` environment variable to forbid the usage of prebuilt binaries.

## Differences to the Specification ##

In the X3DH specification, the identity key is a Curve25519/Curve448 key and [XEdDSA](https://www.signal.org/docs/specifications/xeddsa/) is used to create signatures with it. This library is a little more flexible regarding the identity key. First, you can choose whether to use a Curve25519/Curve448 or an Ed25519/Ed448 key pair for the identity key internally. Second, you can choose whether the public part of the identity key in the bundle is transferred as Curve25519/Curve448 or Ed25519/Ed448. Note that Curve448/Ed448 is currently not supported.

## A Note on Dependencies ##

python-x3dh currently depends on both [cryptography](https://cryptography.io/) and [libnacl](https://libnacl.readthedocs.io/), which are both libraries that offer cryptographic primitives and overlap quite a bit. The reason is that libnacl, which is used by [python-xeddsa](https://github.com/Syndace/python-xeddsa) too, doesn't support HKDF (yet) and cryptography doesn't support converting Ed25519 key pairs to Curve25519. The goal is to drop the dependency on cryptography as soon as libnacl gains support for HKDF.
