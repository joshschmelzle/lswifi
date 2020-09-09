## Notifications

- Use `apprise` to send windows toasts? [https://github.com/caronc/apprise](https://github.com/caronc/apprise).

pip install apprise
pip install pypiwin32

Usage:

```
>>> import apprise
>>> apobj = apprise.Apprise()
>>> apobj.add('windows://')
>>> apobj.notify(body="test", title="yo yo yo")
```

#### Known Issues

1. These toast messages do not persist in notification tray.

2. There might be a scenario where Windows does not permit the display of these messages. My corp machine is not toasting.

```
>>> import apprise
>>> apobj = apprise.Apprise()
>>> apobj.add('windows://')
True
>>> apobj.notify(body="Roam between 00:00:00:00:00:00 and 00:00:00:33:33:33", title="lswifi event")
True
```

## Deploying the application

- Perhaps use [PyOxidizer](https://github.com/indygreg/PyOxidizer)? It can produce binaries that embed Python.

> PyOxidizer is capable of producing a single file executable - with a copy of Python and all its dependencies statically linked and all resources (like .pyc files) embedded in the executable.

## Use Tox to standardize testing in Python


> tox is a generic virtualenv management and test command line tool you can use for:
> 
> checking your package installs correctly with different Python versions and interpreters
> 
> running your tests in each of the environments, configuring your test tool of choice
> 
> acting as a frontend to Continuous Integration servers, greatly reducing boilerplate and merging CI and shell-based testing.


https://tox.readthedocs.io/en/latest/index.html

## Coverage Measurement

Use coverage.py to measure code coverage during test execution. 

https://pypi.org/project/coverage/

## GUI

It would be SICK to have some GUI part of this on Windows - maybe something that sends Toast messages?