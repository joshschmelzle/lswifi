WORKFLOW
========

1. Clone repo
2. Install depends

    ```bash
    python -m pip install -U pip setuptools pip-tools wheel tox
    ```

3. Develop feature or hotfix (recommend adding tests where applicable)
4. Test with `tox` which will run the test driver, check coverage, and generate a new coverage-badge for us automatically.
5. (recommended) check lint with `tox -e lint` which runs `ruff check` and `ruff format --check`.
6. (recommended) check format with `tox -e format` which runs `ruff format`.
7. (recommended) check types with `tox -e typing` which runs mypy on repo.
8. Sanity checks
9. Push code
10. (maintainers only) release by merging a `__version__` bump and a `HISTORY.md` section to `main`. `publish.yml` tags `v<version>` and, after the `pypi` environment is approved, publishes to PyPI. See [PUBLISHING.md](PUBLISHING.md).

pip-compile
-----------

pip-compile can pin our depends for us. use with `pip-compile .\requirements\dev.in` for example. The docs can be found here <https://github.com/jazzband/pip-tools/>.
