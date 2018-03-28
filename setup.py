#!/usr/bin/env python

from distutils.core import setup

setup(
    name = "X3DH",
    version = "0.1.0",
    description = "A python implementation of the Extended Triple Diffie-Hellman key agreement protocol.",
    author = "Tim Henkes",
    url = "https://github.com/Syndace/python-x3dh",
    packages = ["x3dh", "x3dh.exceptions", "x3dh.implementations"],
    requires = ["scci", "pynacl", "hkdf"],
    provides = ["x3dh"]
)
