#!/usr/bin/env python
# -*- coding: utf-8 -*-

import pathlib
from setuptools import setup, find_packages

# The directory containing this file
HERE = pathlib.Path(__file__).parent

# The text of the README file
README = (HERE / "README.md").read_text()

requirements = ["boto3"]
test_requirements = [
    "pytest",
    "pytest-watch",
    "pytest-cov",
    "flake8",
]
setup_requirements = ["pytest-runner", "setuptools>=40.5.0"]

extras = {"test": test_requirements}

setup(
    name="va_ondemand",
    version="0.1.0",
    author="Caglar Ulucenk",
    author_email="culucenk@mozilla.com",
    description="On-demand vulnerability assessment client for vautomator-serverless.",
    long_description=README,
    long_description_content_type="text/markdown",
    url="https://github.com/mozilla/vautomator-client",
    classifiers=[
        "Programming Language :: Python :: 3",
        "License :: OSI Approved :: Mozilla Public License 2.0 (MPL 2.0)",
        "Operating System :: OS Independent",
    ],
    install_requires=requirements,
    license="Mozilla Public License 2.0",
    include_package_data=True,
    packages=find_packages(include=["va_ondemand"]),
    package_data={
        "va_ondemand": [
        ]
    },
    setup_requires=setup_requirements,
    tests_require=test_requirements,
    extras_require=extras,
    test_suite="tests",
    zip_safe=True,
    # Change this
    entry_points={"console_scripts": ["va_ondemand = va_ondemand.__main__:main"]},
)