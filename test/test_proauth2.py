#!/usr/bin/env python

from time import sleep
from pymongo import MongoClient

from proauth2 import Proauth2, Proauth2Error
from proauth2.data_stores import mongo_ds

class TestProauth2():
    def setup( self ):
        self.proauth2 = Proauth2( mongo_ds.DataStore( 'proauth2_tests' ) )

    def teardown( self ):
        db = MongoClient().proauth2_tests
        db.tokens.remove()
        db.nonce_codes.remove()
        db.applications.remove()

    def test_end_to_end( self ):
        uri = 'localhost:5000'
        client_info = self.proauth2.register_app( 'my_test_app', uri )
        print 'client_info: %s' % client_info
        nonce = self.proauth2.request_authorization( client_info['client_id'],
                                                     'test_user@example.com',
                                                     'code',
                                                     uri )
        print 'nonce: %s' % nonce
        token = self.proauth2.request_access_token( client_info['client_id'],
                                                    client_info['client_secret'],
                                                    nonce['code'],
                                                    'authorization_code' )
        print 'token: %s' % token
        user_id = self.proauth2.authenticate_token( token['access_token'] )
        print 'user_id: %s' % user_id
        self.proauth2.revoke_token( token['access_token'] )
        try:
            user_id2 = self.proauth2.authenticate_token( token['access_token'] )
        except Proauth2Error as err:
            if err.message == 'access_denied' and \
            err.error_description == 'token does not exist or has been revoked':
                assert True
            else:
                assert False
