#!/usr/bin/env python
from setuptools import setup

NAME = 'proauth2'
DESCRIPTION = 'An OAuth2 Provider Module for Python'
VERSION = open('VERSION').read().strip()
LONG_DESC = open('README.rst').read()

setup(
    name = NAME,
    version = VERSION,
    author = 'Charles Thomas',
    author_email = 'ch@rlesthom.as',
    packages = [ 'proauth2', 'proauth2.data_stores' ],
    url = 'https://github.com/charlesthomas/%s' % NAME,
    license = 'MIT',
    description = DESCRIPTION,
    long_description = LONG_DESC,
    install_requires = ["motor >= 0.1"],
)
