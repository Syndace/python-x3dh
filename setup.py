from setuptools import setup, find_packages

import os
import sys

version_file_path = os.path.join(
	os.path.dirname(os.path.abspath(__file__)),
	"x3dh",
	"version.py"
)

version = {}

try:
	execfile(version_file_path, version)
except:
	with open(version_file_path) as fp:
		exec(fp.read(), version)

with open("README.md") as f:
    long_description = f.read()

setup(
    name = "X3DH",
    version = version["__version__"],
    description = (
        "A python implementation of the Extended Triple Diffie-Hellman key agreement " +
        "protocol."
    ),
    long_description = long_description,
    long_description_content_type = "text/markdown",
    url = "https://github.com/Syndace/python-x3dh",
    author = "Tim Henkes",
    author_email = "me@syndace.dev",
    license = "MIT",
    packages = find_packages(),
    install_requires = [ "cryptography>=1.7.1", "XEdDSA>=0.4.7,<0.5" ],
    python_requires  = ">=2.7, !=3.0.*, !=3.1.*, !=3.2.*, !=3.3.*, <4",
    zip_safe = False,
    classifiers = [
        "Development Status :: 4 - Beta",

        "Intended Audience :: Developers",

        "Topic :: Communications :: Chat",
        "Topic :: Security :: Cryptography",

        "License :: OSI Approved :: MIT License",

        "Programming Language :: Python :: 2",
        "Programming Language :: Python :: 2.7",

        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.4",
        "Programming Language :: Python :: 3.5",
        "Programming Language :: Python :: 3.6",
        "Programming Language :: Python :: 3.7"
    ]
)
