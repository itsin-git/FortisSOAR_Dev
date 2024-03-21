import json, arrow, mysql.connector
from datetime import datetime
from mysql.connector import errorcode
from connectors.core.connector import get_logger, ConnectorError

logger = get_logger('mysql')


class MySQL(object):
    def __init__(self, config):
        self.hostname = config.get('host')
        self.database = config.get('database')
        self.username = config.get('username')
        self.password = config.get('password')
        self.conn = None

    def make_connection(self):
        try:
            self.conn = mysql.connector.connect(user=self.username, password=self.password,
                                                host=self.hostname, database=self.database)
            if self.conn.is_connected():
                logger.info('Connecting to MySQL database')
            else:
                logger.error('Connection failed')
        except mysql.connector.Error as err:
            if err.errno == errorcode.ER_ACCESS_DENIED_ERROR:
                raise ConnectorError('Access denied/wrong  username or password')
            elif err.errno == errorcode.ER_BAD_DB_ERROR:
                raise ConnectorError('Database does not exists')
            else:
                raise ConnectorError(err)
        except Exception as err:
            logger.exception('{}'.format(err))
            raise ConnectorError(err)


def handler(obj):
    if isinstance(obj, bytearray) or isinstance(obj, bytes):
        return obj.decode(encoding='utf-8')
    elif isinstance(obj, datetime):
        return str(arrow.get(obj))


def list_tables(config, params):
    mysql_obj = MySQL(config)
    try:
        mysql_obj.make_connection()
        cursor = mysql_obj.conn.cursor(dictionary=True)
        cursor.execute('SHOW TABLES;')
        return [json.loads(json.dumps(dict(row), default=handler)) for row in cursor]
    except Exception as e:
        logger.exception('{}'.format(e))
        raise ConnectorError('{}'.format(e))


def list_columns(config, params):
    mysql_obj = MySQL(config)
    query = 'DESCRIBE {0};'.format(params.get('table_name'))
    try:
        mysql_obj.make_connection()
        cursor = mysql_obj.conn.cursor(dictionary=True)
        cursor.execute(query)
        data = [json.loads(json.dumps(dict(row), default=handler)) for row in cursor]
        cursor.close()
        mysql_obj.conn.close()
        return data
    except Exception as e:
        logger.exception('{}'.format(e))
        raise ConnectorError('{}'.format(e))


def run_query(config, params):
    mysql_obj = MySQL(config)
    query = params.get('query_string')
    try:
        mysql_obj.make_connection()
        cursor = mysql_obj.conn.cursor(dictionary=True)
        cursor.execute(query)
        data = [json.loads(json.dumps(dict(row), default=handler)) for row in cursor]
        mysql_obj.conn.commit()
        if not data:
            return{'status': 'success'}
        cursor.close()
        mysql_obj.conn.close()
        return data
    except Exception as e:
        logger.exception('{}'.format(e))
        raise ConnectorError('{}'.format(e))


def _check_health(config):
    mysql_obj = MySQL(config)
    try:
        mysql_obj.make_connection()
        if mysql_obj.conn.is_connected():
            logger.info('Connecting to MySQL database')
            return True
        else:
            raise ConnectorError('Connection failed')
    except Exception as e:
        logger.exception('{}'.format(e))
        raise ConnectorError('{}'.format(e))


operations = {
    'list_tables': list_tables,
    'list_columns': list_columns,
    'run_query': run_query
}
