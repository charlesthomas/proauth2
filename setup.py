#!/usr/bin/env python
from distutils.core import setup

NAME = 'proauth2'
DESCRIPTION = 'An OAuth2 Provider Module for Python'
VERSION = open( 'VERSION' ).read().strip()
LONG_DESC = open( 'README' ).read()

setup(
    name = NAME,
    version = VERSION,
    author = 'Charles Thomas',
    author_email = 'ch@rlesthom.as',
    packages = [ '%s' % NAME, ],
    url = 'http://code.cha.rlesthom.as/%s' % NAME,
    license = 'MIT',
    description = DESCRIPTION,
    long_description = LONG_DESC,
)
