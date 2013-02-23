#!/usr/bin/env python
'''
as i understand the spec, there are theorietically multiple ways to pass
client_id / client_secret information, which require different authentication
methods.
this file exists so multiple methods can be added without mucking up the rest of
the code.
currently only direct comparison of passed and stored secrets has been
implemented.
to add more, write the function here, and add the function as a value in the
auth_methods dictionary below, keyed by the function name.
'''

def direct_auth( key, secret ):
    '''
    directly compare the stored secret and the passed secret.
    '''
    if key == secret: return True
    return False

auth_methods = {}
auth_methods['direct_auth'] = direct_auth
