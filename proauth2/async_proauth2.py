#!/usr/bin/env python
from string import ascii_letters, digits
from random import choice
from datetime import timedelta
from time import time

from tornado.gen import engine, Task

from proauth2 import Proauth2Error
from auth_methods import *

class AsyncProauth2(object):
    '''
    Proauth2 is a framework-independent OAuth2 Provider module.
    AsyncProauth2 class requires a DataStore object.
    (see proauth2.data_store for additional information)
    '''
    def __init__(self, data_store):
        self.data_store = data_store

    @engine
    def register_app(self, name, redirect_uri, callback):
        '''
        register_app takes an application name and redirect_uri
        It generates client_id (client_key) and client_secret,
        then stores all of the above in the data_store,
        and returns a dictionary containing the client_id and client_secret.
        '''
        client_id = self._generate_token()
        client_secret = self._generate_token(64)
        yield Task(self.data_store.store, 'applications', client_id=client_id,
                   client_secret=client_secret, name=name,
                   redirect_uri=redirect_uri)
        callback({'client_id':client_id, 'client_secret':client_secret})

    @engine
    def request_authorization(self, client_id, user_id, response_type,
                              redirect_uri=None, scope=None, state=None,
                              expires=600, callback=None):
        '''
        request_authorization generates a nonce, and stores it in the data_store along with the
        client_id, user_id, and expiration timestamp.
        It then returns a dictionary containing the nonce as "code," and the passed
        state.
        ---
        response_type MUST be "code." this is directly from the OAuth2 spec.
        this probably doesn't need to be checked here, but if it's in the spec I
        guess it should be verified somewhere.
        scope has not been implemented here. it will be stored, but there is no
        scope-checking built in here at this time.
        if a redirect_uri is passed, it must match the registered redirect_uri.
        again, this is per spec.
        '''
        if response_type != 'code':
            raise Proauth2Error('invalid_request',
                                'response_type must be "code"', state=state)
        client = yield Task(self.data_store.fetch, 'applications',
                            client_id=client_id)
        if not client: raise Proauth2Error('access_denied')

        if redirect_uri and client['redirect_uri'] != redirect_uri:
            raise Proauth2Error('invalid_request', "redirect_uris don't match")

        nonce_code = self._generate_token()
        expires = time() + expires
        try:
            yield Task(self.data_store.store, 'nonce_codes', code=nonce_code,
                       client_id=client_id, expires=expires, user_id=user_id,
                       scope=scope)
        except Proauth2Error as e:
            e.state = state
            raise e

        callback({'code':nonce_code, 'state':state})

    @engine
    def request_access_token(self, client_id, key, code, grant_type,
                             redirect_uri=None, method='direct_auth',
                             callback=None):
        '''
        request_access_token validates the client_id and client_secret, using the
        provided method, then generates an access_token, stores it with the user_id
        from the nonce, and returns a dictionary containing an access_token and
        bearer token.
        ---
        from the spec, it looks like there are different types of
        tokens, but i don't understand the disctintions, so someone else can fix
        this if need be.
        regarding the method: it appears that it is intended for there to be
        multiple ways to verify the client_id. my assumption is that you use the
        secret as the salt and pass the hashed of the client_id or something, and
        then compare hashes on the server end. currently the only implemented method
        is direct comparison of the client_ids and client_secrets.
        additional methods can be added to proauth2.auth_methods
        '''
        if grant_type != 'authorization_code':
            raise Proauth2Error('invalid_request',
                                 'grant_type must be "authorization_code"')

        yield Task(self._auth, client_id, key, method)
        user_id = yield Task(self._validate_request_code, code, client_id)
        access_token = self._generate_token(64)
        yield Task(self.data_store.store, 'tokens', token=access_token,
                   user_id=user_id, client_id=client_id)

        callback({'access_token':access_token, 'token_type':'bearer'})

    @engine
    def authenticate_token(self, token, callback):
        '''
        authenticate_token checks the passed token and returns the user_id it is
        associated with. it is assumed that this method won't be directly exposed to
        the oauth client, but some kind of framework or wrapper. this allows the
        framework to have the user_id without doing additional DB calls.
        '''
        token_data = yield Task(self.data_store.fetch, 'tokens', token=token)
        if not token_data:
            raise Proauth2Error('access_denied',
                                'token does not exist or has been revoked')
        callback(token_data['user_id'])

    @engine
    def revoke_token(self, token, callback):
        '''
        revoke_token removes the access token from the data_store
        '''
        yield Task(self.data_store.remove, 'tokens', token=token)
        callback()

    @engine
    def _auth(self, client_id, key, method, callback):
        '''
        _auth - internal method to ensure the client_id and client_secret passed with
        the nonce match
        '''
        available = auth_methods.keys()
        if method not in available:
            raise Proauth2Error('invalid_request',
                                'unsupported authentication method: %s'
                                'available methods: %s' % \
                                (method, '\n'.join(available)))
        client = yield Task(self.data_store.fetch, 'applications',
                            client_id=client_id)
        if not client: raise Proauth2Error('access_denied')
        if not auth_methods[method](key, client['client_secret']):
            raise Proauth2Error('access_denied')
        callback()

    @engine
    def _validate_request_code(self, code, client_id, callback):
        '''
        _validate_request_code - internal method for verifying the the given nonce.
        also removes the nonce from the data_store, as they are intended for
        one-time use.
        '''
        nonce = yield Task(self.data_store.fetch, 'nonce_codes', code=code)
        if not nonce:
            raise Proauth2Error('access_denied', 'invalid request code: %s' % code)
        if client_id != nonce['client_id']: 
            raise Proauth2Error('access_denied', 'invalid request code: %s' % code)
        user_id = nonce['user_id']
        expires = nonce['expires']
        yield Task(self.data_store.remove, 'nonce_codes', code=code,
                   client_id=client_id, user_id=user_id)

        if time() > expires:
            raise Proauth2Error('access_denied', 'request code %s expired' % code)

        callback(user_id)

    def _generate_token(self, length=32):
        '''
        _generate_token - internal function for generating randomized alphanumberic
        strings of a given length
        '''
        return ''.join(choice(ascii_letters + digits) for x in range(length))
