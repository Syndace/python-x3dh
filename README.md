[![PyPI](https://img.shields.io/pypi/v/X3DH.svg)](https://pypi.org/project/X3DH/)
[![PyPI - Python Version](https://img.shields.io/pypi/pyversions/X3DH.svg)](https://pypi.org/project/X3DH/)
[![Build Status](https://travis-ci.org/Syndace/python-x3dh.svg?branch=stable)](https://travis-ci.org/Syndace/python-x3dh)
[![Documentation Status](https://readthedocs.org/projects/python-x3dh/badge/?version=latest)](https://python-x3dh.readthedocs.io/en/latest/?badge=latest)

# python-x3dh #

A Python implementation of the [Extended Triple Diffie-Hellman key agreement protocol](https://signal.org/docs/specifications/x3dh/).

## Installation ##

python-x3dh depends on two system libraries, [libxeddsa](https://github.com/Syndace/libxeddsa)>=2,<3 and [libsodium](https://download.libsodium.org/doc/).

Install the latest release using pip (`pip install X3DH`) or manually from source by running `pip install .` (preferred) or `python setup.py install` in the cloned repository. The installation requires libsodium and the Python development headers to be installed. If a locally installed version of libxeddsa is available, [python-xeddsa](https://github.com/Syndace/python-xeddsa) (a dependency of python-x3dh) tries to use that. Otherwise it uses prebuilt binaries of the library, which are available for Linux, MacOS and Windows on the amd64 architecture, and potentially for MacOS arm64 too. Set the `LIBXEDDSA_FORCE_LOCAL` environment variable to forbid the usage of prebuilt binaries.

## Differences to the Specification ##

In the X3DH specification, the identity key is a Curve25519/Curve448 key and [XEdDSA](https://www.signal.org/docs/specifications/xeddsa/) is used to create signatures with it. This library does not support Curve448, however, it supports Ed25519 in addition to Curve25519. You can choose whether the public part of the identity key in the bundle is transferred as Curve25519 or Ed25519. Refer to [the documentation](https://python-x3dh.readthedocs.io/) for details.

## Testing, Type Checks and Linting ##

python-x3dh uses [pytest](https://docs.pytest.org/en/latest/) as its testing framework, [mypy](http://mypy-lang.org/) for static type checks and both [pylint](https://pylint.pycqa.org/en/latest/) and [Flake8](https://flake8.pycqa.org/en/latest/) for linting. All tests/checks can be run locally with the following commands:

```sh
$ pip install --upgrade pytest pytest-asyncio mypy pylint flake8
$ mypy --strict x3dh/ setup.py tests/
$ pylint x3dh/ setup.py tests/
$ flake8 x3dh/ setup.py tests/
$ pytest
```

## Documentation ##

View the documentation on [readthedocs.io](https://python-x3dh.readthedocs.io/) or build it locally, which requires the Python packages listed in `docs/requirements.txt`. With all dependencies installed, run `make html` in the `docs/` directory. You can find the generated documentation in `docs/_build/html/`.

## Travis CI ##

The project used to be built using Travis CI, which was amazing. Sadly, Travis fully closed their open-source support. I have yet to migrate somewhere else, until then the project will not be automatically tested.
