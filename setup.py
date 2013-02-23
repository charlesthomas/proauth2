#!/usr/bin/env python
from distutils.core import setup
from os.path import dirname, join

NAME = 'proauth2'
DESCRIPTION = 'An OAuth2 Provider Module for Python'
VERSION = open( join( dirname( __file__ ), 'VERSION' ) ).read()
LONG_DESC = open( join( dirname( __file__ ), 'README.rst' ) ).read()

setup(
    name = NAME,
    version = VERSION,
    author = 'Charles Thomas',
    author_email = 'ch@rlesthom.as',
    packages = [ '%s' % NAME, ],
    url = 'http://code.cha.rlesthom.as/%s' % NAME,
    license = 'LICENSE.txt',
    description = DESCRIPTION,
    long_description = LONG_DESC,
    install_requires = [
        'pymongo == 2.4.1',
    ],
)
