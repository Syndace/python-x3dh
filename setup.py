from setuptools import setup, find_packages

with open("README.md") as f:
    long_description = f.read()

setup(
    name = "X3DH",
    version = "0.4.3",
    description = "A python implementation of the Extended Triple Diffie-Hellman key agreement protocol.",
    long_description = long_description,
    long_description_content_type = "text/markdown",
    url = "https://github.com/Syndace/python-x3dh",
    author = "Tim Henkes",
    author_email = "tim@cifg.io",
    license = "MIT",
    packages = find_packages(),
    install_requires = [ "hkdf==0.0.3", "XEdDSA>=0.3.6" ],
    python_requires  = ">=2.6, !=3.0.*, !=3.1.*, !=3.2.*, <4",
    zip_safe = True,
    classifiers = [
        "Development Status :: 3 - Alpha",

        "Intended Audience :: Developers",

        "Topic :: Communications :: Chat",
        "Topic :: Security :: Cryptography",

        "License :: OSI Approved :: MIT License",

        "Operating System :: OS Independent",

        "Programming Language :: Python :: Implementation :: CPython",

        "Programming Language :: Python :: 2",
        "Programming Language :: Python :: 2.6",
        "Programming Language :: Python :: 2.7",

        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.3",
        "Programming Language :: Python :: 3.4",
        "Programming Language :: Python :: 3.5",
        "Programming Language :: Python :: 3.6",
        "Programming Language :: Python :: 3.7"
    ]
)
