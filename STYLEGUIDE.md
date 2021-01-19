Style Guide
===========

Dependencies
------------

- Goal is to have no dependencies on external library.
- Anything in the Python Standard Library is safe to use.

Python Naming conventions
-------------------------

- class names should use `UpperCamelCase`
- constant names should be `CAPITALIZED_WITH_UNDERSCORES`
- other names should use `lowercase_separated_by_underscores`
- private variables/methods should start with an underscore: `_myvar`
- some special class methods are surrounded by two underscores: `__init__`

Exceptions
----------

- Native Wifi's wlanapi.h wrapper code.

CamelCase
---------

When using abbreviations in `CamelCase`, capitalize all the letters of the abbreviation. `Dot11SSID` is better than `Dot11Ssid`.

Formatting and Linting
----------------------

You should be linting the code with `tox -e lint` and running `tox -e format` prior to submitting a PR.

### black

All code should be formatted with [black](https://github.com/ambv/black/).

### flake8

All code should be linted and reviewed with [flake8](http://flake8.pycqa.org/en/latest/)

class design
------------

Implement `__repr__` for any class you implement.

Implement `__str__` if you think it would be useful to have a string version which errs on the side of readability.

Rule of thumb:  `__repr__` is for developers, `__str__` is for customers.

IDE
---

If you need an IDE recommendation, use Visual Studio Code (VSC). Otherwise, use what makes you happy.
### Python and VSCode

If you use VSC, you should use Python and Pylance extensions.

[Using Python environments in VS Code](https://code.visualstudio.com/docs/python/environments).
[Linting Python in VS Code](https://code.visualstudio.com/docs/python/linting#_troubleshooting-linting).
[.env](https://code.visualstudio.com/docs/python/environments) is for [PYTHONPATH](https://docs.python.org/3/using/cmdline.html#envvar-PYTHONPATH).
