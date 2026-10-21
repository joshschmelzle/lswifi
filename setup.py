# -*- coding: utf-8 -*-
#
# lswifi - a CLI-centric Wi-Fi scanning tool for Windows
# Copyright (c) 2025 Josh Schmelzle
# SPDX-License-Identifier: BSD-3-Clause
#  _              _  __ _
# | |_____      _(_)/ _(_)
# | / __\ \ /\ / / | |_| |
# | \__ \\ V  V /| |  _| |
# |_|___/ \_/\_/ |_|_| |_|

import os
import sys

try:
    from setuptools import setup  # type: ignore
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

# Packaging metadata lives in pyproject.toml. PEP 621 has no Platform field.
setup(platforms=["win32"])
