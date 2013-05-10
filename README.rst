========
proauth2
========
An OAuth2 provider module for Python

Disclaimer: I almost certainly implemented this wrong.
------------------------------------------------------
I decided I wanted to implement OAuth2 for an app I'm building, and I couldn't find a provider written in Python, so I decided to make one. I tried to follow the spec as closely as possible **up to the point that this module would work for my needs.**

Functionality
-------------
**proauth2 is *not* designed to be directly exposed to OAuth2 clients, but to act as a helper to a framework or other server**
i.e. user acceptance of oauth2 client's access request is **NOT** handled here. It's assumed that you will handle this *before* calling the request\_authorization method.

This module can:

- register an oauth client application, generating client\_id and client\_secret
- generate a nonce code for a given client\_id for a given user\_id
- generate an access token after validating the nonce code, client\_id, and client\_secret
- take an access token and either throw an exception if it's invalid, or return the user\_id associated to the token, if valid
- revoke tokens

Not Implemented
---------------
There are probably more things not implemented here than I can list. Off the top of my head are:

- refresh tokens
- scopes
- access tokens of a type other than "bearer"
- implicit grants

Requirements
------------
There are no non-standard modules used in proauth2 *outside of the DataStores*. Each DataStore will almost certainly require an extra module of some kind. The only currently implemented DataStore is for MongoDB. As such, pymongo is required. However, if someone actually finds this project and adds a new DataStore to it, pymongo will no longer be required, and something else might be required in its place.

*see pip\_requirements.txt*

Examples
--------
example.py includes a full working runnable example of each of the methods in the Proauth2 object. It **does not** include Proauth2Error examples, DataStore examples (outside of what is built into the object methods), or authentication methods.
Hopefully the documetation inside those files is sufficient.

*see example.py*

Tests
-----
I only wrote a single, end-to-end test; it passes. It was implemented with **nosetests**, so you will need to install **nose** to run it. The test can be found in tests/test\_proauth2.py

client\_id / client\_secret authentication methods
--------------------------------------------------
As I understand the spec, there are multiple ways to authenticate the client\_id / client\_secret pair. Currently, only direct comparison of the stored and sent client\_secrets has been implemented, however adding additional methods should be as simple as writing a function in proauth2/auth\_methods.py and adding the function to the allowed\_methods dictionary.

What the hell is a DataStore?
-----------------------------
In order for proauth2 to work, there must be a way to store, fetch, and remove data (tokens, nonces, etc). For example, a SQL database. Rather than making a specific storage medium a hard requirement of the module, I have attempted to create a storage framework that can be easily implemented for other storage options. Currently, the only option available is MongoDB, because it was what I could build this with the fastest.

The Basics
~~~~~~~~~~
In proauth2/data\_stores, you'll see mongo\_ds.py. This is the MongoDB implementation of a proauth2 DataStore. To add, say, a MySQL DataStore, I would suggest proauth2/data\_stores/mysql\_ds.py.

Regardless of the name of the file, a DataStore **must** contain class called DataStore, with the following methods:

- init
- fetch
- remove
- store

Initialization
~~~~~~~~~~~~~~
The *init* method must take the following parameters, **in order**:

1. database - the database name (default: proauth2)
2. host - the hostname the database server runs on (default: 'localhost' is recommended)
3. port - the port the database server is listening on (default: whatever the default port is for the implemented DataStore; e.g. 27017 for MongoDB)
4. user - the username to connect to the database (default: None)
5. pwd - the password to connect to the database

The init method should then make a connection to the database with the given parameters, and set the connection as self.db

Fetch
~~~~~
The *fetch* method must take the following:

- table - the name of the table (collection in MongoDB) to fetch data from. (e.g. applications, nonce\_codes, tokens)
- kwargs - kwargs should be a dictionary containing key/value pairs representing the field name in the table and the value in that field. (e.g. {name='my app',client\_id=12345} would correspond to the SQL query "select from table where name='my app' and client\_id=12345")

The fetch method must search the DataStore as appropriate for its storage method, and return **exactly one** record that matches the kwargs query in the table.
*If there is no match, fetch should return **None***

Remove
~~~~~~
The *remove* method must take the following:

- table
- kwargs

(see *fetch* for an explanation of these parameters)

*remove* should remove the record(s) matching the kwargs parameters, and return nothing

Store
~~~~~
The *store* method must take the following:

- table
- kwargs

(see *fetch* for an explanation of these parameters)

**It is *highly* recommended that *store* call the *validate* method in proauth2/data\_stores/validate.py to ensure valid data is stored** *see proauth2/data\_stores/mongo\_ds.py to see this used*

*store* should verify that the table's key is not already in use, and raise a Proauth2Error if it is (*especially* if this is not built into the DataStore's storage method - *see proauth2/data\_stores/mongo\_ds.py to see this used*)

*store* stores the passed data into the DataStore and returns nothing
