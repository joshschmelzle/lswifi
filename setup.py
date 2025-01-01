# -*- coding: utf-8 -*-

import os
import sys
from codecs import open

try:
    from setuptools import find_packages, setup  # type: ignore
except ModuleNotFoundError:
    raise ImportError("setuptools is required ...")

# 'python setup.py build' shortcut
if sys.argv[-1] == "build":
    os.system("python setup.py sdist bdist_wheel")
    sys.exit()

# 'python setup.py check' shortcut
if sys.argv[-1] == "check":
    os.system("python -m twine check dist/*")
    sys.exit()

# 'python setup.py deploy' shortcut
if sys.argv[-1] == "deploy":
    os.system("python -m twine upload dist/*")
    sys.exit()

here = os.path.abspath(os.path.dirname(__file__))

# load the package's __version__.py module as a dictionary
about = {}  # type: ignore
with open(os.path.join(here, "lswifi", "__version__.py"), "r", "utf-8") as f:
    exec(f.read(), about)  # nosec

try:
    with open("README-PYPI.md", "r") as f:
        readme = f.read()
except FileNotFoundError:
    readme = about["__description__"]

packages = find_packages()


def parse_requires(_list: list) -> list:
    """Parse and return a requires list from pip-compiled files."""
    requires = []
    trims = ["#", "piwheels.org"]
    for require in _list:
        if any(match in require for match in trims):
            continue
        requires.append(require)
    requires = list(filter(None, requires))  # remove "" from list
    return requires


with open(os.path.join(here, "requirements", "dev.txt")) as f:
    dev_requires = f.read().splitlines()

dev_requires = parse_requires(dev_requires)

extras = {"dev": dev_requires}

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
    python_requires=">=3.9",
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
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
        "Programming Language :: Python :: 3.12",
        "Programming Language :: Python :: 3.13",
        "Intended Audience :: Information Technology",
        "Intended Audience :: System Administrators",
        "Intended Audience :: Telecommunications Industry",
        "Topic :: Utilities",
        "Topic :: System :: Networking",
        "Topic :: System :: Networking :: Monitoring",
        "Environment :: Win32 (MS Windows)",
        "Operating System :: Microsoft :: Windows :: Windows 10",
        "Operating System :: Microsoft :: Windows :: Windows 11",
    ],
)
