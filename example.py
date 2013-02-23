#!/usr/bin/env python
from pprint import PrettyPrinter

from proauth2 import Proauth2,Proauth2Error
from proauth2.data_stores.mongo_ds import DataStore

# pp = PrettyPrinter( indent=4 )
pp = PrettyPrinter()

#The DataStore object is passed on initialization of the Proauth2 object
#Therefore, the DataStore must be initialized first
data_store = DataStore( database='proauth2-test', host='localhost', port=27017,
                        user=None, pwd=None )

#Initialize Proauth2 object, passing DataStore object
proauth2_object = Proauth2( data_store )

#Registering an app
uri = 'http://someurl.com/oauth2/redirect'
client_info = proauth2_object.register_app( 'app name', redirect_uri=uri )
print 'client_info:'
pp.pprint( client_info )
print '-' * 25

#Requesting authorization 
#(see README - it's assumed you've already been granted permission by the user)
nonce = proauth2_object.request_authorization( client_id=client_info['client_id'],
                                               user_id='test@example.com',
                                               response_type='code',
                                               redirect_uri=uri )
print 'nonce object:'
pp.pprint( nonce )
print '-' * 25

#Requesting access token
token = proauth2_object.request_access_token( client_id=client_info['client_id'],
                                              key=client_info['client_secret'],
                                              code=nonce['code'],
                                              grant_type='authorization_code' )
print 'token object:'
pp.pprint( token )
print '-' * 25

#Authenticating token
user_id = proauth2_object.authenticate_token( token['access_token'] )
print 'user_id associated to token:'
pp.pprint( user_id )
print '-' * 25

#Revoking token
proauth2_object.revoke_token( token['access_token'] )
