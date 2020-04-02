from setuptools import setup, find_packages

import os
import sys

source_root = os.path.join(os.path.dirname(os.path.abspath(__file__)), "x3dh")

version = {}
with open(os.path.join(source_root, "version.py")) as f:
	exec(f.read(), version)
version = version["__version__"]

project = {}
with open(os.path.join(source_root, "project.py")) as f:
	exec(f.read(), project)
project = project["project"]

with open("README.md") as f:
    long_description = f.read()

classifiers = [
    "Intended Audience :: Developers",

    "License :: OSI Approved :: MIT License",

    "Programming Language :: Python :: 3",
    "Programming Language :: Python :: 3 :: Only",

    "Programming Language :: Python :: 3.6",
    "Programming Language :: Python :: 3.7",
    "Programming Language :: Python :: 3.8"
]

classifiers.extend(project["categories"])

if version["tag"] == "alpha":
    classifiers.append("Development Status :: 3 - Alpha")

if version["tag"] == "beta":
    classifiers.append("Development Status :: 4 - Beta")

if version["tag"] == "stable":
    classifiers.append("Development Status :: 5 - Production/Stable")

del project["categories"]
del project["year"]

setup(
    version = version["short"],
    long_description = long_description,
    long_description_content_type = "text/markdown",
    license = "MIT",
    packages = find_packages(),
    install_requires = [
        "XEdDSA>=1.0.0,<2",
        "cryptography>=2.6.1,<3",
        "libnacl>=1.6.1,<=2",
        "packaging>=19,<21"
    ],
    python_requires = ">=3.6,<4",
    include_package_data = True,
    zip_safe = False,
    classifiers = classifiers,
    **project
)
