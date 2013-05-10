#!/usr/bin/env python
from motor import MotorClient, Op
from tornado.gen import engine, Task

from proauth2 import Proauth2Error
from proauth2.data_stores.validate import validate

class DataStore(object):
    '''
    async_mongo_ds.DataStore is an Asynchronous DataStore object for storing /
    fetching / removing records for proauth2, which uses a mongodb database for
    storage.  all proauth2 DataStore objects should take the same init params,
    have the same functions, and work in the same way at an object level.  for
    additional information, see "What the hell is a DataStore in the README
    '''
    def __init__(self, database='proauth2', host='localhost', port=27017,
                  user=None, pwd=None):
        '''
        initialize a mongodb connection to mongodb://user:pass@host:port
        use database
        '''
        if user and pwd:
            connection_string = 'mongodb://%s:%s@%s:%s' % \
                                (user, pwd, host, port)
        else:
            connection_string = 'mongodb://%s:%s' % \
                                (host, port)
        self.db = MotorClient(connection_string).open_sync()[database]

    @engine
    def fetch(self, collection, **kwargs):
        '''
        return one record from the collection whose parameters match kwargs
        ---
        kwargs should be a dictionary whose keys match column names (in
        traditional SQL / fields in NoSQL) and whose values are the values of
        those fields.
        e.g. kwargs={name='my application name',client_id=12345}
        '''
        callback = kwargs.pop('callback')
        data = yield Op(self.db[collection].find_one, kwargs)
        callback(data)

    @engine
    def remove(self, collection, **kwargs):
        '''
        remove records from collection whose parameters match kwargs
        '''
        callback = kwargs.pop('callback')
        yield Op(self.db[collection].remove, kwargs)
        callback()

    @engine
    def store(self, collection, **kwargs):
        '''
        validate the passed values in kwargs based on the collection,
        store them in the mongodb collection
        '''
        callback = kwargs.pop('callback')
        key = validate(collection, **kwargs)
        data = yield Task(self.fetch, collection, **{key: kwargs[key]})
        if data is not None:
            raise Proauth2Error('duplicate_key')
        yield Op(self.db[collection].insert, kwargs)
        callback()
