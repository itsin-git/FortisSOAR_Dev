import json
from datetime import datetime

import arrow
from sqlalchemy import create_engine
from sqlalchemy.sql import text
from voluptuous import (
    Required, All, Length, Range,
    Schema, Optional, Coerce, In
)
from connectors.core.connector import get_logger, ConnectorError
from connectors.core.result import Result
logger = get_logger("database.builtins")


def make_query(config, params, *args, **kwargs):
    """
    Takes a database connector out of the defined connectors and makes a query
    with it.

    :param str query: The text of the query to send to the database
    :param str connector_name: Optional named connector to use, if not specified
        the most recently defined database connector will be used
    :return: Results of the query
    :rtype: list
    :raises Exception: If the database connector has not been configured
        properly
    """
    try:
        connector = DatabaseConnector(config)
        if not connector:
            logger.warn('No database connection configured')
            raise Exception('No database connection configured')
        return connector.text_query(params['query_string'])
    except Exception as exp:
        raise ConnectorError(str(exp))


class DatabaseConnector():
    """
    Represents a database resource. Note that it does not represent an actual
    connection to a database, it handles all of that internally. It is more of a
    configuration object that aids in making queries to its configured database.
    """

    driver_map = {
        'postgresql': 'postgresql+psycopg2',
        'mssql': 'mssql+pymssql',
        'mysql': 'mysql+mysqlconnector',
    }

    db_config_schema = Schema({
        Required('host'): All(str, Length(min=1)),
        Optional('port', default=0): All(Coerce(int), Range(min=0, max=65535)),
        Required('engine'): All(str, In(driver_map.keys())),
        Required('username'): str,
        Required('password'): str,
        Required('database'): str,
    })

    def __init__(self, db_config, *args, **kwargs):
        """
        Creates a new database connector. The connector does not make any actual
        connections until a query is constructed. It is configured by a dict
        object of the following form::

            {
                'host': '<host string>',
                'port': <port number>,
                'engine': '<database type>',
                'username': '<string>',
                'password': '<string>',
                'database': '<database name>'
            }

        Database type must be one of: 'postgresql', or 'mssql', or 'mysql'

       :param Schema db_config: Contains information describing the database.
       :return: An object that can be used to make queries against its
           configured database.
       :rtype: DatabaseConnector
        """
        # pop any extra keys
        allowed_keys = ['host', 'port', 'engine', 'username', 'password', 'database']
        extra_keys = [key for key in db_config.keys() if key not in allowed_keys]
        for extra_key in extra_keys:
            db_config.pop(extra_key, None)
        db_config = self.db_config_schema(db_config)
        engine = self.driver_map[db_config['engine']]

        self.dsn = '{engine}://{user}:{password}@{host}:{port}/{db}'.format(
            engine=engine,
            user=db_config['username'],
            password=db_config['password'],
            host=db_config['host'],
            port=db_config['port'],
            db=db_config['database'],
        )
        self.engine = create_engine(self.dsn, echo=False)

    def make_query(self, query, *args, **kwargs):
        """
        Actually makes a query. This will open and close a connection as part of
        it function. Returns all result at once, no cursor support.

        :param `sqlalchemy.sql.expression.Executable` query: The prepared
            query to execute
        :return: A list of dictionaries. Each dict represents a row in the
            returned database data. The dictionaries are of the form
            <column-name>:<column-value>
        :rtype: list
        """
        is_fetch_query = False
        with self.engine.connect() as conn:
            results = conn.execute(query)
            is_fetch_query = results.returns_rows
            if is_fetch_query:
                results = results.fetchall()

        if not is_fetch_query:
            result = Result()
            result.set_result(status="Success", message="Query executed successfully")
            return result

        # handles other unserializeable types
        # like datetimes and byte arrays
        def _handler(obj):
            if isinstance(obj, bytearray) or isinstance(obj, bytes):
                return obj.decode(encoding='utf-8')
            elif isinstance(obj, datetime):
                return str(arrow.get(obj))
            else:
                err = "Unserializable object of type {0} :: {1}".format(
                    type(obj),
                    obj
                )
                logger.error(err)
                raise TypeError(err)

        # http://i.imgur.com/jUdTCRt.jpg
        return [json.loads(json.dumps(dict(res), default=_handler))
                for res in results]

    def text_query(self, query_string, *args, **kwargs):
        """
        Constructs a text query object, and executes said object against the
        configured database.

        .. caution::
            This is just a raw SQL string, with all your favorite sql injection
            features included. Use with care.

        :return: Result of the query. See `:func:make_query`
        """
        return self.make_query(text(query_string))

    def select_query(self, table, columns, *args, **kwargs):
        pass
