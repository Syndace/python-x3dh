[![PyPI](https://img.shields.io/pypi/v/X3DH.svg)](https://pypi.org/project/X3DH/)
[![PyPI - Python Version](https://img.shields.io/pypi/pyversions/X3DH.svg)](https://pypi.org/project/X3DH/)
[![Build Status](https://github.com/Syndace/python-x3dh/actions/workflows/test-and-publish.yml/badge.svg)](https://github.com/Syndace/python-x3dh/actions/workflows/test-and-publish.yml)
[![Documentation Status](https://readthedocs.org/projects/python-x3dh/badge/?version=latest)](https://python-x3dh.readthedocs.io/)

# python-x3dh #

A Python implementation of the [Extended Triple Diffie-Hellman key agreement protocol](https://signal.org/docs/specifications/x3dh/).

## Installation ##

Install the latest release using pip (`pip install X3DH`) or manually from source by running `pip install .` in the cloned repository.

## Differences to the Specification ##

In the X3DH specification, the identity key is a Curve25519/Curve448 key and [XEdDSA](https://www.signal.org/docs/specifications/xeddsa/) is used to create signatures with it. This library does not support Curve448, however, it supports Ed25519 in addition to Curve25519. You can choose whether the public part of the identity key in the bundle is transferred as Curve25519 or Ed25519. Refer to [the documentation](https://python-x3dh.readthedocs.io/) for details.

## Testing, Type Checks and Linting ##

python-x3dh uses [pytest](https://docs.pytest.org/en/latest/) as its testing framework, [mypy](http://mypy-lang.org/) for static type checks and both [pylint](https://pylint.pycqa.org/en/latest/) and [Flake8](https://flake8.pycqa.org/en/latest/) for linting. All tests/checks can be run locally with the following commands:

```sh
$ pip install --upgrade pytest pytest-asyncio pytest-cov mypy pylint flake8 setuptools
$ mypy --strict x3dh/ setup.py tests/
$ pylint x3dh/ setup.py tests/
$ flake8 x3dh/ setup.py tests/
$ pytest --cov=x3dh --cov-report term-missing:skip-covered
```

## Documentation ##

View the documentation on [readthedocs.io](https://python-x3dh.readthedocs.io/) or build it locally, which requires the Python packages listed in `docs/requirements.txt`. With all dependencies installed, run `make html` in the `docs/` directory. You can find the generated documentation in `docs/_build/html/`.
