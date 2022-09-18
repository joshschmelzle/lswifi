# -*- coding: utf-8 -*-

import os
try:
    from setuptools import find_packages, setup
except:
    raise ImportError("setuptools is required to install lswifi ...")

here = os.path.abspath(os.path.dirname(__file__))

about = {}
with open(os.path.join(here, "lswifi", "__version__.py")) as f:
    exec(f.read(), about)

try:
    with open("README.md", "r") as f:
        readme = f.read()
except FileNotFoundError:
    long_description = about["__description__"]

extras = {
    "test": [
        "tox",
        "black",
        "isort",
        "autoflake",
        "mypy",
        "pytest",
        "pytest-cov",
        "coverage-badge",
        "scapy",
    ],
}

setup(
    name=about["__title__"],
    version=about["__version__"],
    packages=find_packages(exclude=("tests", "test")),
    description=about["__description__"],
    long_description=readme,
    long_description_content_type="text/markdown",
    url=about["__url__"],
    author=about["__author__"],
    author_email=about["__author_email__"],
    python_requires=">=3.7",
    extras_require=extras,
    entry_points={"console_scripts": ["lswifi=lswifi.__main__:main"]},
    license="BSD 3-Clause License",
    platforms=["win32"],
    keywords=[
        "lswifi",
        "scanner",
        "wireless",
        "wifi",
        "802.11",
        "wlan",
        "rlan",
        "native wifi",
        "wlanapi",
    ],
    classifiers=[
        "Natural Language :: English",
        "Development Status :: 3 - Alpha",
        "Environment :: Console",
        "Programming Language :: Python :: 3 :: Only",
        "Programming Language :: Python :: 3.7",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Intended Audience :: Information Technology",
        "Intended Audience :: System Administrators",
        "Intended Audience :: Telecommunications Industry",
        "Topic :: Utilities",
        "Topic :: System :: Networking",
        "Topic :: System :: Networking :: Monitoring",
        "Environment :: Win32 (MS Windows)",
        "Operating System :: Microsoft :: Windows :: Windows 10",
        "Operating System :: Microsoft :: Windows :: Windows 11"
    ],
)
