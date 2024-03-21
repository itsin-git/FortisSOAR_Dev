import logging
import socket
import sys
import os
from threading import Thread
import argparse
import json
import re
import time
from os import path
from imap_utils import _select_folder, _make_imap_client, logout_client, LOG_FILE_PATH
sys.path.append(path.abspath('/opt/cyops-integrations/integrations'))
from connectors.imap.errors.error_constants import *
from integrations.crudhub import make_request
threads = {}
client_count = 0
HOST = '0.0.0.0'
MAX_LENGTH = 4096
idle_timeout = 30
SSL_VERIFY = False
cs_host = 'localhost'
logging.basicConfig(filename=LOG_FILE_PATH, level=logging.WARN,
                    format='%(asctime)s %(levelname)s %(module)s %(funcName)s(): %(message)s')
logger = logging.getLogger(__name__)
serversocket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
serversocket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)


def find_byte_value(data, find_value, key = None):
    for value in data:
        str_value = value.decode("utf-8").strip("\\")
        if str_value == find_value:
            return True
    return False

def find_unread_mail(responses):
    try:
        for response_flag in responses:
            command = response_flag[1].decode("utf-8")
            if command == 'FETCH' and response_flag[0]>0:
                try:
                    fetch_result = response_flag[2][3]
                except Exception as e:
                    response_len = len(response_flag[2])
                    fetch_result = response_flag[2][response_len-1]
                if not find_byte_value(fetch_result, 'Seen') and not find_byte_value(fetch_result, 'Deleted'):
                    return True
            elif command == 'EXISTS' and response_flag[0]>0:
                return True
        return False
    except Exception as e:
        logger.exception("No mails found which where marked as unread in IMAP idle mode ERROR :: {0}".format(e))
        return False


def get_key(host, port, username, source):
    return host.upper() + '-' + str(port) + '-' + username + '-' + source

class NotifierThread(Thread):
    def __init__(self, imap_config, username, trigger, thread_key, source):
        Thread.__init__(self)
        self.imap_config = imap_config
        self.username = username
        self.trigger = trigger
        self.thread_key = thread_key
        self.source = source
        self._create_imap_client()

    def _create_imap_client(self):
        self.client = _make_imap_client(**self.imap_config)
        _select_folder(self.client, self.source)

    def forward_to_cyops(self):
        full_uri = '/api/triggers/1/' + self.trigger
        try:
            response = make_request(full_uri, 'POST', body={'from_notification': True}, __async=True, verify=False)
            task_id = response.get('task_id')
            if task_id:
                logger.info('Playbook for fetching mail triggered successfully')
        except Exception as e:
            logger.exception(
                "Error occurred while triggering the CyOPs playbook ' {0} ' ERROR :: {1}".format(self.trigger, e))
            raise Exception(
                "Error occurred while triggering the CyOPs playbook ' {0} ' ERROR :: {1}".format(self.trigger, e))

    def run(self,**kwargs):
        try:
            global client_count
            idle_mode = False
            self.forward_to_cyops()
            while True:
                if not threads.get(self.thread_key, False):
                    break
                else:
                    if not threads[self.thread_key]['result']:
                        break
                if not idle_mode:
                    count = 0
                    try:
                        self.client.idle()
                        logger.info('Idle mode on')
                        idle_mode = True
                        count = 0
                    except Exception as e1:
                        logger.exception(cs_imap_7.format(count, str(e1)))
                        count += 1
                        try:
                            logout_client(self.client)
                        except Exception as e2:
                            logger.error("Failed to logout %s"%str(e2))
                        try:
                            self._create_imap_client()
                        except Exception as e3:
                            logger.error(cs_imap_20.format(str(e3)))
                            if 'Server Unavailable' in str(e3):
                                #Untill the server is not ready we will sleep for 30 sec
                                logger.info('Sleeping for 30 sec for mail server to come up')
                                time.sleep(30)

                        if(count>10):
                            raise Exception(cs_imap_8.format(self.username,str(e)))

                if idle_mode:
                    # Wait for up to 30 seconds for an IDLE response
                    try:
                        responses = self.client.idle_check(idle_timeout)
                        if responses:
                            count = 0
                            command = responses[0][1].decode("utf-8")
                            if command == 'EXISTS':
                                logger.info('New mail received, triggering CyOps playbook :: {0}'.format(self.trigger))
                                self.forward_to_cyops()
                            elif command == 'EXPUNGE':
                                logger.info('Email has been moved from the source folder')
                            else:
                                if find_unread_mail(responses):
                                    logger.info('Mail marked as unread triggering CyOps playbook :: {0}'.format(self.trigger))
                                    self.forward_to_cyops()
                        else:
                            count += 1
                            total_time = (idle_timeout*count)/60
                            if total_time >= 20:
                                logger.info('Restarting Idle Mode after 20 min')
                                idle_mode = False
                                self.client.idle_done()
                                self.client.noop()
                    except Exception as e:
                        logger.exception(cs_imap_9.format(str(e)))
            self.client.idle_done()
            self.client.noop()
            logger.info("logging out: %s" %self.username)
            logout_client(self.client)
            client_count -= 1
        except Exception as e:
            client_count -= 1
            logger.error("{0} ERROR :: {1}".format(cs_imap_6, str(e)).format(self.username))

def start_server(host, port, ssl, username, password, source, verify, trigger):
    global threads, client_count
    thread_key = get_key(host, port, username, source)
    if not threads.get(thread_key, False):
        threads[thread_key] = {"result": False, "message": "","threadobj": {}}
    if not threads[thread_key]['result']:
        try:
            imap_config = {'host': host, 'port': port, 'username': username, 'password': password, 'ssl': ssl, 'verify': verify}
            thread_instance = NotifierThread(imap_config, username, trigger, thread_key, source)
            thread_instance.start()
            threads[thread_key]['result'] = True
            threads[thread_key]['threadobj'] = thread_instance
            client_count += 1
            message = 'Notification service started for username: %s' % (username)
        except Exception as e:
            logger.exception("{0} ERROR :: {1}".format(cs_imap_5 ,str(e)))
            threads[thread_key]['message'] = cs_imap_5
            return -1, str(e)
    else:
        message = cs_imap_4.format(host,port,username)
        return -1, message
    return 0, message

def stop_server(username, port, host, source):
    global threads, client_count
    thread_key = get_key(host, port, username, source)
    if threads.get(thread_key, False):
        thread_len = len(threads)
        threads.pop(thread_key)
        message = 'Notification Service has been stopped for username: %s' % (username)
        if thread_len < 2:
            timeout = time.time() + 40
            while time.time() < timeout:
                time.sleep(2)
                if client_count <= 0:
                    break
    else:
        message = cs_imap_13.format(host,port,username)
        logger.exception(message)
    return 0, message

def shutdown_server():
    global threads
    threads = {}
    timeout = time.time() + 50
    while time.time() < timeout:
        time.sleep(2)
        if client_count <= 0:
            break
    return 0, "All notification services are been stopped."

def health_check(username, port, host, source):
    thread_key = get_key(host, port, username, source)
    if threads.get(thread_key, False):
        if threads[thread_key]['result']:
            if not threads[thread_key]['threadobj'].isAlive():
                message = cs_imap_6.format(username)
                logger.warn(message)
                return -1, message
            else:
                message = cs_imap_4.format(host,port,username)
                return 0, message
        else:
            logger.error(threads[thread_key]['message'])
            return -1, threads[thread_key]['message']
    else:
        message = cs_imap_12.format(host,port,username)
        logger.error(message)
        return -1, message

def handle(clientsocket):
    payload_bytes = clientsocket.recv(MAX_LENGTH)
    if payload_bytes:
        payload = payload_bytes.decode('utf-8')
        parser = argparse.ArgumentParser(description='Imap Mail Notification Actions')
        parser.add_argument('--start', help='Start Server', action='store_true', default=False, required=False)
        parser.add_argument('--stop', help='Stop Server', action='store_true', default=False, required=False)
        parser.add_argument('--exit', help='Stop Server', action='store_true', default=False, required=False)
        parser.add_argument('--check', help='Check Health', action='store_true', default=False, required=False)
        parser.add_argument('--host', help='Configuration for mail notification', required=False)
        parser.add_argument('--port', help='Port for server', required=False)
        parser.add_argument('--ssl', help='SSL for server', required=False)
        parser.add_argument('--username', help='Mail username to forward data', required=False)
        parser.add_argument('--password', help='Mail password to forward data', required=False)
        parser.add_argument('--source', help='Folder name to read mails', required=False)
        parser.add_argument('--verify', help='Folder name to keep read mails', required=False)
        parser.add_argument('--trigger', help='Configuration for trigger playbook', required=False)
        status = -1
        args_parsed = False
        try:
            # so that the main program does not exit if parsing fails
            args = parser.parse_args([p for p in re.split("( |\\\".*?\\\"|'.*?')", payload) if p.strip()])
            args_parsed = True
        except SystemExit as se:
            message = cs_imap_10
            logger.exception("{0} ERROR :: {1}".format(cs_imap_10,str(se)))
        if args_parsed:
            try:
                if args.exit:
                    status, message = shutdown_server()
                else:
                    if not args.port:
                        raise Exception(cs_imap_2.format("IMAP Port"))
                    if not args.host:
                        raise Exception(cs_imap_2.format("IMAP Host"))
                    if not args.username:
                        raise Exception(cs_imap_2.format("Username for mailbox"))
                    if not args.source:
                        raise Exception(cs_imap_2.format("Source Folder from mailbox"))
                    port = int(args.port)
                    host = args.host
                    if args.ssl and args.ssl.lower() == 'false':
                        ssl = False
                    else:
                        ssl = True
                    username = args.username
                    source = args.source
                    if args.stop:
                        status, message = stop_server(username, port, host, source)
                    elif args.check:
                        status, message = health_check(username, port, host, source)
                    else:
                        password = args.password
                        if not password:
                            raise Exception(cs_imap_2.format("Password for mailbox"))
                        trigger = args.trigger
                        if not trigger:
                            raise Exception(cs_imap_2.format("Trigger to trigger CyOps playbook"))
                        
                        if args.verify and args.verify.lower() == 'false':
                            verify = False
                        else:
                            verify = True
                        if args.start:
                            status, message = start_server(host, port, ssl, username, password, source,
                                                           verify,trigger)
                        else:
                            raise Exception(cs_imap_3)
            except Exception as e:
                logger.exception(e)
                message = str(e)
        clientsocket.sendall(json.dumps({'status': status, 'message': message}).encode('utf-8'))
        clientsocket.close()
        if args_parsed:
            if args.exit or (args.stop and not client_count):
                serversocket.close()
                os._exit(0)
# Bind socket to local host and port
try:
    PORT = int(sys.argv[1])
    serversocket.bind((HOST, PORT))
except socket.error as msg:
    logger.error(cs_imap_1.format(HOST,PORT,msg))
    os._exit(0)
serversocket.listen(10)

while True:
    (clientsocket, address) = serversocket.accept()
    handle(clientsocket)

# now keep talking with the client
