import os
from setuptools import setup

def read(fname):
    return open(os.path.join(os.path.dirname(__file__), fname)).read()

setup(
    name = "mdm-example-cloud-client",
    version = "0.1dev",
    author = "Paolo Shishido",
    description = ("A demonstration of how to use OPSWAT's MetaDefender Cloud APIs to scan a file against multiple "
                   "anti-malware engines, perform data sanitization on document files, and more"),
    license = "MIT",
    packages = ["pkg",],
    long_description = read("README.md"),
    install_requires = [
        "requests>=2.19.1"
    ],
    classifiers = [
        "Programming Language :: Python",
        "Natural Language :: English",
        "Intended Audience :: Developers",
        "License :: OSI Approved :: MIT License"
    ]
)