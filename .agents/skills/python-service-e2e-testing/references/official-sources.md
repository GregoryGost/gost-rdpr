# Python Service E2E Official Sources

Use these sources for non-browser Python service E2E testing.

## Python testing

- pytest documentation: https://docs.pytest.org/en/stable/
- pytest fixtures: https://docs.pytest.org/en/stable/how-to/fixtures.html
- pytest temporary directories: https://docs.pytest.org/en/stable/how-to/tmp_path.html
- pytest monkeypatch: https://docs.pytest.org/en/stable/how-to/monkeypatch.html
- pytest markers: https://docs.pytest.org/en/stable/example/markers.html
- pytest import mechanisms and `sys.path` / `PYTHONPATH`: https://docs.pytest.org/en/stable/explanation/pythonpath.html
- pytest-asyncio documentation: https://pytest-asyncio.readthedocs.io/en/stable/
- pytest-xdist documentation: https://pytest-xdist.readthedocs.io/en/stable/
- coverage.py documentation: https://coverage.readthedocs.io/

## Python process, filesystem, and runtime boundaries

- Python `subprocess`: https://docs.python.org/3/library/subprocess.html
- Python `tempfile`: https://docs.python.org/3/library/tempfile.html
- Python `pathlib`: https://docs.python.org/3/library/pathlib.html
- Python `os.environ`: https://docs.python.org/3/library/os.html#os.environ
- Python `time.monotonic`: https://docs.python.org/3/library/time.html#time.monotonic
- Python `unittest.mock`: https://docs.python.org/3/library/unittest.mock.html
- Python `asyncio`: https://docs.python.org/3/library/asyncio.html

## HTTP and service boundaries

- FastAPI testing: https://fastapi.tiangolo.com/tutorial/testing/
- Starlette TestClient: https://www.starlette.io/testclient/
- HTTPX documentation: https://www.python-httpx.org/
- pytest-httpserver documentation: https://pytest-httpserver.readthedocs.io/
- RESPX documentation: https://lundberg.github.io/respx/
- pytest-httpx documentation: https://colin-b.github.io/pytest_httpx/

## Disposable dependencies

- Testcontainers for Python: https://testcontainers-python.readthedocs.io/en/latest/
- Testcontainers PostgreSQL module: https://testcontainers-python.readthedocs.io/en/latest/modules/postgres/README.html
- Docker Compose: https://docs.docker.com/compose/
- Docker Compose file reference: https://docs.docker.com/reference/compose-file/

Project runtime, entrypoints, E2E command, dependency policy, migrations, seed data, container policy, environment policy, and artifact policy come from `CODEX_PROJECT.md` and the target repository.
