Style Guide
===========

Defaults
--------

The default output when `lswifi` is run should contain data in each column. For this reason we would not want to display QBSS information because not all neighboring networks will support QBSS.

The output should display without wrapping on 1080p with 150% scaling.

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
