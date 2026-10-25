Publishing and Distribution
===========================

Building an exe with PyInstaller
--------------------------------

Create venv if not exists:

```bash
python -m venv venv
```

Activate venv, install requires, del dist, and run PyInstaller:

```bash
.\venv\scripts\activate.ps1
python -m pip install -r .\requirements\dev.in
del .\dist\ -r
python -m PyInstaller --onefile --name "lswifi" ".\lswifi\__main__.py"
```

Building and uploading to PyPi
------------------------------

Install depends:

```bash
python -m pip install -U pip wheel setuptools twine
```

To create a source archive and a wheel for your package, you can run the following command:

```bash
python setup.py sdist bdist_wheel
```

or

```bash
python setup.py build
```

This will create two files in a newly created dist directory, a source archive and a wheel:

Newer versions of Twine (1.12.0 and above) can also check that your package description will render properly on PyPI.

You can run twine check on the files created in dist:

```bash
python -m twine check dist/*
```

or

```bash
python setup.py check
```

Upload to production pypi:

```bash
python -m twine upload dist/*
```

or

```bash
python setup.py deploy
```

You will need to setup API keys in .pypirc placed in the user directory. See [PyPA docs on .pypirc file](https://packaging.python.org/en/latest/specifications/pypirc/).

Versioning and releasing
------------------------

Use semantic versions, tagged `v<major>.<minor>.<patch>` (for example `v0.3.2`).

- *major* is a breaking change
- *minor* stays compatible with previous versions
- *patch* is a bug fix

Merge the release to `main` with `__version__` bumped in `lswifi/__version__.py` and a section for that version in `HISTORY.md`. The release workflow tags that commit `v<version>` and opens a GitHub release whose notes are that `HISTORY.md` section. If the version did not change, or the tag already exists, it does nothing.

That workflow then runs the publish workflow. The publish workflow checks the tag against `__version__` and uploads to PyPI only after the protected `pypi` environment is approved. Publishing a GitHub release by hand runs the same publish workflow.
