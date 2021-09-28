# IDEAS

Some ideas to explore with this project.

## Directed Scans

One idea is to do a directed scan with built in APIs, but I'm not sure this really works.

So what I do instead (for a "directed scan") is filter the scan results depending on what the user requests.

I moved this over from <TODO.md>:

- [ ] Use WlanScan pDot11Ssid to specify a SSID to be scanned. This is for a directed scan on a particular a SSID.

## Notifications and Toast Messages

- Use `apprise` to send windows toasts? [https://github.com/caronc/apprise](https://github.com/caronc/apprise).

```bash
pip install apprise
pip install pypiwin32
```

Usage:

```test
>>> import apprise
>>> apobj = apprise.Apprise()
>>> apobj.add('windows://')
>>> apobj.notify(body="test", title="yo yo yo")
```

Some known issues with this approach:

1. These toast messages do not persist in notification tray.

2. There might be a scenario where Windows does not permit the display of these messages. My corp machine is not toasting.

```test
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

I'm currently deploying to PyPI, which means `lswifi` can be installed and updated with `pip install -U lswifi`.

## Use Tox to standardize testing in Python

I now have a `tox.ini` in the base of this repo.

> tox is a generic virtualenv management and test command line tool you can use for:
>
> checking your package installs correctly with different Python versions and interpreters
>
> running your tests in each of the environments, configuring your test tool of choice
>
> acting as a frontend to Continuous Integration servers, greatly reducing boilerplate and merging CI and shell-based testing.

<https://tox.readthedocs.io/en/latest/index.html>

## Coverage Measurement

Use coverage.py to measure code coverage during test execution.

<https://pypi.org/project/coverage/>

## Displaying Security Branding

One thought is to parse out the RSN IEs and categorize according to branding. I'm back burning this from TODO.md and placing it here because I do not plan to work on this.

The user will need to know and interpret the auth/unicast/group mapping themself.

For example, `PSK/AES/AES` is WPA2-PSK. `SAE/AES/AES` is WPA3-PSK. And if you see `PSK/AES,TKIP/TKIP` on a network you control, you should mitigate that.

## Graphical Interface

While it would be awesome to have a GUI for this, I think that is out of scope for what I am willing to commit to this project. `lswifi` is intended to be a CLI centric application. Think of it as something that expands on the ideas of `netsh wlan show networks` and addresses the short-comings.

## WDI

There may be a way to enable some sort of monitor mode on Windows including packet injection and such. This would be via the WDI (WLAN Device Driver Interface) which is the new Universal Windows driver model for Windows 10. Some WLAN device manufacturers can write a single WDI miniport driver that runs on all device platforms, and requires less code than the previous native WLAN driver model. All new WLAN features introduced in Windows 10 require WDI-based drivers. <https://docs.microsoft.com/en-us/windows-hardware/drivers/network/wifi-universal-driver-model>

One idea may be to explore use of WDI (WLAN Device Driver Interface) filter drivers - perhaps for certain Radio Tap Headers?
