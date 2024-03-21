import argparse
import sys
from log_helper import logger
import socket
import shlex
import json
from struct import unpack
from embeddings_helper_common import refresh_collection, get_similar_documents

SERVER_HOST = 'localhost'
PORT = 10447
serversocket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
serversocket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)


def check_health():
    return True, "Listener available"


def handle(client_socket):
    message = {}
    BUFF_SIZE = 4096
    payload_bytes = b''
    bs = client_socket.recv(8)
    (length,) = unpack('>Q', bs)
    while len(payload_bytes) < length:
        to_read = length - len(payload_bytes)
        payload_bytes += client_socket.recv(BUFF_SIZE if to_read > BUFF_SIZE else to_read)

    if payload_bytes:
        payload = payload_bytes.decode()
        parser = argparse.ArgumentParser(description='AI Assistant')
        parser.add_argument("--check", help="Check Health", action="store_true")
        parser.add_argument("--similar", help="Get documents matching a query string", action="store_true")
        parser.add_argument("--refresh_model", help="Refresh the training dataset", action="store_true")
        parser.add_argument("--exit", help="Stop the server", action="store_true")
        parser.add_argument("--query_str", help="Query String", type=str, required="--similar" in payload,
                            action="store")
        parser.add_argument("--n_results", help="Number of matches to results", type=int, required="--similar" in payload,
                            action="store")
        parser.add_argument("--task_type", help="Task Type", type=str, required=False, action="store")
        parser.add_argument("--training_folder", help="Folder containing the configuration export with playbooks to be "
                                                      "trained on", type=str, required="--refresh_model" in payload,
                            action="store")

        status = -1
        args_parsed = False
        try:
            args = parser.parse_args(shlex.split(payload))
            args_parsed = True
        except SystemExit as se:
            message = se
            logger.exception(se)
        except ValueError:
            error = 'The payload is too large for the server'
            logger.exception(error)
            status, message = -1, error
        if args_parsed:
            try:
                if args.check:
                    status, message = check_health()
                elif args.refresh_model:
                    status, message = refresh_collection(args.training_folder)
                elif args.similar:
                    status, message = get_similar_documents(args.query_str, args.n_results, args.task_type)
                elif not args.exit:
                    raise Exception("Unsupported function")
            except Exception as err:
                logger.exception(err)
                message = str(err)

        client_socket.sendall(json.dumps({'status': status, 'message': message}).encode('utf-8'))
        client_socket.close()

        if args.exit:
            logger.info("Server is shutting down")
            serversocket.close()
            sys.exit()


try:
    serversocket.bind((SERVER_HOST, PORT))
    logger.info("Server bind for IP: {}, Port: {}".format(SERVER_HOST, PORT))
except socket.error as msg:
    logger.exception("Bind failed: {}".format(msg))
    sys.exit()

logger.info("Server is listening")
serversocket.listen(5)

while True:
    (client, address) = serversocket.accept()
    logger.info("**** {0} ****".format(client))
    handle(client)