MAKEFLAGS += --always-make

VERSION ?= $(shell python3 -c "from xpw_locker.attribute import __version__; print(__version__)")

all: build test


release: all
	if [ -n "${VERSION}" ]; then \
		git tag -a v${VERSION} -m "release v${VERSION}"; \
		git push origin --tags; \
	fi

version:
	@echo ${VERSION}


upload:
	python3 -m pip install --upgrade xpip-upload
	xpip-upload --config-file .pypirc dist/*


build-prepare:
	python3 -m pip install --upgrade xpip-build
build-clean:
	find . -type d -name "__pycache__" -exec rm -rf {} +
	rm -rf build dist *.egg-info
build: build-prepare build-clean
	python3 -m build --sdist --wheel


install-requirements:
	python3 -m pip install --upgrade -r requirements.txt
install: install-requirements
	python3 -m pip install --force-reinstall --no-deps dist/*.whl
uninstall:
	python3 -m pip uninstall -y xpw-locker
reinstall: uninstall install


test-prepare: install-requirements
	python3 -m pip install --upgrade mock flake8 pylint pytest pytest-cov
flake8:
	flake8 xpw_locker
pylint:
	pylint $(shell git ls-files xpw_locker/*.py)
pytest:
	pytest --cov --cov-config=.coveragerc --cov-report=term-missing --cov-report=xml --cov-report=html
pytest-clean:
	rm -rf .pytest_cache
test: test-prepare flake8 pylint pytest
test-clean: pytest-clean


clean-cover:
	rm -rf cover .coverage coverage.xml htmlcov
clean-tox:
	rm -rf .stestr .tox
clean: build-clean test-clean clean-cover clean-tox
