Publishing and Distribution
===========================

Building and uploading to PyPi
------------------------------

Install depends:

```
python -m pip install -U pip wheel setuptools twine
```

To create a source archive and a wheel for your package, you can run the following command:

```
python setup.py sdist bdist_wheel
```

This will create two files in a newly created dist directory, a source archive and a wheel:

Newer versions of Twine (1.12.0 and above) can also check that your package description will render properly on PyPI.

You can run twine check on the files created in dist:

```
python -m twine check dist/*
```

Upload to production pypi:

```
python -m twine upload dist/*
```

Enter your username and password when requested.

Versioning and Git Tagging
--------------------------

Suggest to use semantic versioning like so:

```
v<major>.<minor>.<patch>
```

Where:

- *major* is version number where there are breaking modifications (new version not compatible with previous)
- *minor* is version number compatible with previous versions
- *patch* is an increment for bug fix / hot fix / patch fix on your software

To create a Git tag (on the latest commit (aka HEAD) of current branch) with a message use the following:

```
git tag -a <tag_name> -m "message"
```

So if you want a tag on your `main` branch with a message `"new hotfix release for v0.1.42"`:

Confirm branch with `git status | findstr branch` on Windows or `git status | grep branch` *nix.

```
git tag -a v0.1.42 -m "new hotfix release for v0.1.42"
```

Verify your Git tag was successfully created:

```
git tag
git tag -n
```

Push your tags:

```
git push --tags
```