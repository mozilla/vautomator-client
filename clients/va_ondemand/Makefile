ROOT_DIR        := $(shell dirname $(realpath $(lastword $(MAKEFILE_LIST))))
MODULE_NAME     := $(notdir $(patsubst %/,%,$(ROOT_DIR)))
SHELL		:= /bin/bash

all:
	@echo 'Available make targets:'
	@grep '^[^#[:space:]].*:' Makefile

.PHONY: install
install:
	# Installs as egg
	python3 setup.py install
	# Installs via pip
	pip3 install .

.PHONY: build
build:
	python3 setup.py build

.PHONY: flake
flake:
	flake8 setup.py
	flake8 tests/*.py
	flake8 $(MODULE_NAME)/*.py

.PHONY: test
test:
	pytest tests/

.PHONY: clean
clean:
	rm -rf .pytest_cache
	rm -rf __pycache__
	rm -rf *.egg-info
	rm -rf .eggs
	rm -rf build
	rm -rf dist
