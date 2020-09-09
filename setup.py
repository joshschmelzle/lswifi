# -*- coding: utf-8 -*-

import os
from setuptools import find_packages, setup

here = os.path.abspath(os.path.dirname(__file__))

about = {}
with open(os.path.join(here, "lswifi", "__version__.py")) as f:
    exec(f.read(), about)

try:
    with open("README.md", "r") as f:
        readme = f.read()
except FileNotFoundError:
    long_description = about["__description__"]

requires = []

setup(
    name=about["__title__"],
    version=about["__version__"],
    packages=find_packages(exclude=("tests", "test")),
    description=about["__description__"],
    long_description=readme,
    long_description_content_type="text/markdown",
    author=about["__author__"],
    author_email=about["__author_email__"],
    python_requires=">3.6,",
    # install_requires=requires,
    entry_points={"console_scripts": ["lswifi=lswifi.__main__:main"]},
    url=about["__url__"],
    keywords=[
        "lswifi",
        "scanner",
        "wireless",
        "windows",
        "wifi",
        "802.11",
        "wlan",
        "native wifi",
        "wlanapi",
    ],
    license="",
    classifiers=[
        "Natural Language :: English",
        "Development Status :: 3 - Alpha",
        "Programming Language :: Python :: 3.7",
        "Programming Language :: Python :: 3.8",
        "Intended Audience :: Information Technology",
        "Intended Audience :: System Administrators",
        "Topic :: Utilities",
        "Topic :: System :: Networking :: Monitoring",
        "Environment :: Win32 (MS Windows)",
        "Operating System :: Microsoft :: Windows :: Windows 10",
    ],
)
