MAKEFLAGS += --always-make

VERSION := $(shell python3 setup.py --version)

all: build reinstall test


release: all
	if [ -n "${VERSION}" ]; then \
		git tag -a v${VERSION} -m "release v${VERSION}"; \
		git push origin --tags; \
	fi

version:
	@echo ${VERSION}


clean-cover:
	rm -rf cover .coverage coverage.xml htmlcov
clean-tox:
	rm -rf .stestr .tox
clean: build-clean test-clean clean-cover clean-tox


upload:
	python3 -m pip install --upgrade xpip-upload
	xpip-upload --config-file .pypirc dist/*


build-prepare:
	python3 -m pip install --upgrade -r requirements.txt
	python3 -m pip install --upgrade xpip-build
build-clean:
	xpip-build --debug setup --clean
build: build-prepare build-clean
	xpip-build --debug setup --all


install:
	python3 -m pip install --force-reinstall --no-deps dist/*.whl
uninstall:
	python3 -m pip uninstall -y xpw-locker
reinstall: uninstall install


test-prepare:
	python3 -m pip install --upgrade mock pylint flake8 pytest pytest-cov
pylint:
	pylint $(shell git ls-files xpw_locker/*.py)
flake8:
	flake8 xpw_locker --count --select=E9,F63,F7,F82 --show-source --statistics
	flake8 xpw_locker --count --exit-zero --max-complexity=10 --max-line-length=127 --statistics
pytest:
	pytest --cov=xpw_locker --cov-report=term-missing --cov-report=xml --cov-report=html --cov-config=.coveragerc --cov-fail-under=100
pytest-clean:
	rm -rf .pytest_cache
test: test-prepare pylint flake8 pytest
test-clean: pytest-clean
