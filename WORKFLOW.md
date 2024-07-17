WORKFLOW
========

1. Clone repo
2. Install depends

    ```bash
    python -m pip install -U pip setuptools pip-tools wheel tox
    ```

3. Develop feature or hotfix (recommend adding tests where applicable)
4. Test with `tox` which will run the test driver, check coverage, and generate a new coverage-badge for us automatically.
5. (recommended) check lint with `tox -e lint` which checks repo with black and isort.
6. (recommended) check format with `tox -e format` which runs flake8 on repo.
7. (recommended) check types with `tox -e typing` which runs mypy on repo.
8. Sanity checks
9. Push code
10. (maintainers only) build package and deploy to PyPI

 - `tox`
 - `python setup.py build`
 - `python setup.py check`
 - `python setup.py deploy`

pip-compile
-----------

pip-compile can pin our depends for us. use with `pip-compile .\requirements\dev.in` for example. The docs can be found here <https://github.com/jazzband/pip-tools/>.
