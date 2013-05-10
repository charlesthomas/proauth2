#!/usr/bin/env python
import logging
from time import sleep

from pymongo import MongoClient
from tornado.gen import Task
from tornado.testing import AsyncTestCase

from proauth2 import AsyncProauth2, Proauth2Error
from proauth2.data_stores import async_mongo_ds

class TestAsyncProauth2(AsyncTestCase):
    def setUp(self):
        super(TestAsyncProauth2, self).setUp()
        self.proauth2 = AsyncProauth2(async_mongo_ds.DataStore('proauth2_tests'))

    def tearDown(self):
        pass
        # db = MongoClient().proauth2_tests
        # db.tokens.remove()
        # db.nonce_codes.remove()
        # db.applications.remove()
        # self.stop()

    def test_end_to_end(self):
        uri = 'localhost:5000'
        client_info = yield Task(self.proauth2.register_app, 'my_test_app', uri)
        print 'client_info: %s' % client_info

        nonce = yield Task(self.proauth2.request_authorization,
                           client_info['client_id'], 'test_user@example.com',
                           'code', uri)
        print 'nonce: %s' % nonce

        token = yield Task(self.proauth2.request_access_token,
                           client_info['client_id'],
                           client_info['client_secret'],
                           nonce['code'],
                           'authorization_code')
        print 'token: %s' % token

        user_id = yield Task(self.proauth2.authenticate_token,
                             token['access_token'])
        print 'user_id: %s' % user_id

        yield Task(self.proauth2.revoke_token, token['access_token'])
        try:
            user_id2 = yield Task(self.proauth2.authenticate_token,
                                  token['access_token'])
            assert False
        except Proauth2Error as err:
            if err.message == 'access_denied' and \
            err.error_description == 'token does not exist or has been revoked':
                assert True
            else:
                assert False
        self.stop()
