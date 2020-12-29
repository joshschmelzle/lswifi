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