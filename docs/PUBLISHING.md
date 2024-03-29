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

Versioning and Git Tagging
--------------------------

Suggest to use semantic versioning like so:

```bash
v<major>.<minor>.<patch>
v1.0.10
```

Where:

- *major* is version number where there are breaking modifications (new version not compatible with previous)
- *minor* is version number compatible with previous versions
- *patch* is an increment for bug fix / hot fix / patch fix on your software

To create a Git tag (on the latest commit (aka HEAD) of current branch) with a message use the following:

```bash
git tag -a <tag_name> -m "message"
```

So if you want a tag on your `main` branch with a message `"new hotfix release for v0.1.42"`:

Confirm branch with `git status | findstr branch` on Windows or `git status | grep branch` *nix.

```bash
git tag -a v0.1.42 -m "new hotfix release for v0.1.42"
```

Verify your Git tag was successfully created:

```bash
git tag
git tag -n
```

Push your tags:

```bash
git push --tags
```
