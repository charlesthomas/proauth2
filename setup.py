#!/usr/bin/env python
from distutils.core import setup
from os.path import dirname, join

NAME = 'proauth2'
DESCRIPTION = 'An OAuth2 Provider Module for Python'
VERSION = open( join( dirname( __file__ ), 'VERSION' ) ).read()

setup(
    name = NAME,
    version = VERSION,
    description = DESCRIPTION,
    author = 'Charles Thomas',
    author_email = 'ch@rlesthom.as',
    url = 'http://code.cha.rlesthom.as/%s' % NAME,
)
