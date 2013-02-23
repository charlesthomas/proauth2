#!/usr/bin/env python
from pymongo import MongoClient
from proauth2 import Proauth2Error
from proauth2.data_stores.validate import validate

class DataStore( object ):
    '''
    mongo_ds.DataStore is a DataStore object for storing / fetching / removing
    records for proauth2, which uses a mongodb database for storage.
    all proauth2 DataStore objects should take the same init params, have the
    same functions, and work in the same way at an object level.
    for additional information, see "What the hell is a DataStore in the README
    '''
    def __init__( self, database='proauth2', host='localhost', port=27017,
                  user=None, pwd=None ):
        '''
        initialize a mongodb connection to mongodb://user:pass@host:port
        use database
        '''
        if user and pwd:
            connection_string = 'mongodb://%s:%s@%s:%s' \
            % ( user, pwd, host, port )
            self.db = MongoClient( connection_string )[database]
        else:
            self.db = MongoClient( host, port )[database]

    def fetch( self, collection, **kwargs ):
        '''
        return one record from the collection whose parameters match kwargs
        ---
        kwargs should be a dictionary whose keys match column names (in
        traditional SQL / fields in NoSQL) and whose values are the values of
        those fields.
        e.g. kwargs={name='my application name',client_id=12345}
        '''
        return self.db[collection].find_one( kwargs )

    def remove( self, collection, **kwargs ):
        '''
        remove records from collection whose parameters match kwargs
        '''
        self.db[collection].remove( kwargs )

    def store( self, collection, **kwargs ):
        '''
        validate the passed values in kwargs based on the collection,
        store them in the mongodb collection
        '''
        key = validate( collection, **kwargs )
        if self.fetch( collection, **{ key : kwargs[key] } ):
            raise Proauth2Error( 'duplicate_key' )
        self.db[collection].insert( kwargs )
