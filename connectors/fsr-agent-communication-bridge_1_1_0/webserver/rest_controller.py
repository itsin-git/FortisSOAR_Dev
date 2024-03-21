import json
import mimetypes
import subprocess
import sys
import web
import urllib.parse

from subprocess import check_call

from scheme import validate_token
from app import log
from app.config import config
from app.make_rest_api_call import MakeRestApiCall
from app.helper import connector_body, connector_body_execute

from cheroot.server import HTTPServer
from cheroot.ssl.builtin import BuiltinSSLAdapter

logger = log.get_logger(__name__)

PORT = config['SERVER']['port']

urls = (
    # Keeping the URL consistent with URL from FortiSOAR instance.
    '/input', 'RestController',
    '/manual-input', 'ManualInputController',
    '/', 'Static',
    '/(.*)', 'Static',
)

process_name = 'rest_controller.py'


class Static:
    def GET(self, file='index.html', media='static'):
        try:
            f = open(media + '/' + file, 'r')
            _mimetype = mimetypes.MimeTypes().guess_type(media + '/' + file)[0]
            web.header('Content-Type', _mimetype)
            return f.read()
        except:
            return ''


class ManualInputController:

    def GET(self):
        input_id = web.input().get('inputId', None)
        token = web.ctx.env.get('HTTP_AUTHORIZATION')
        web.header('Content-Type', 'application/json')
        if not (input_id and token):
            message = 'Input ID  and token value are required'
            return web.BadRequest(message=message)
        if not validate_token(token, input_id, logger):
            message = 'Invalid token or token might be expired'
            logger.error(message)
            return web.Unauthorized(message=message)

        url = config['INTEGRATION']['EXECUTE_URL']
        body = connector_body('fsr-agent-communication-bridge', 'fetch_maunal_input_details',
                              params={"input_id": input_id, "token": token})
        mk = MakeRestApiCall()
        response = mk.make_request(endpoint=url, json_data=body, method='POST',
                                   headers={'content-type': 'application/json'})
        if response.get('Error'):
            message = 'Manual Input ID not found or input already provided'
            return web.NotFound(message=message)
        return json.dumps(response)


class RestController:

    def GET(self):
        host = web.ctx.get('host')
        input_id = web.input().get('inputId', None)
        token = web.input().get('token', None)
        logger.info(input_id)
        render = web.template.render('templates/')
        web.header('Content-Type', 'text/html')
        if not (input_id and token):
            message = 'Input ID  and token value are required'
            logger.error(message)
            return render.error('Server Error', message)
        if not validate_token(token, input_id, logger):
            message = 'Invalid token or token might be expired'
            logger.error(message)
            return render.error('Server Error', message)
        url = config['INTEGRATION']['EXECUTE_URL']
        body = connector_body('fsr-agent-communication-bridge', 'fetch_maunal_input_details',
                              params={"input_id": input_id, "token": token})
        mk = MakeRestApiCall()
        response = mk.make_request(endpoint=url, json_data=body, method='POST',
                                   headers={'content-type': 'application/json'})
        logger.info(response)
        if response.get('Error'):
            message = 'Manual Input data already provided for given ID'
            return render.error('Error', message)
        encoded_params = urllib.parse.urlencode({'token': token, 'inputId': input_id})
        url = 'https://' + host + '?' + encoded_params
        return '<html><body onload=\"javascript:window.location.href =\'' + url + '\'\"></body></html>'

    def POST(self):
        token = web.ctx.env.get('HTTP_AUTHORIZATION')
        web_data = json.loads(web.data())
        if not validate_token(token, web_data.get('manual_input_id'), logger):
            return web.unauthorized("Unauthenticated request")
        url = config['INTEGRATION']['EXECUTE_URL']
        body = connector_body_execute('fsr-agent-communication-bridge', 'resume_playbook',
                                      params={"web_data": web_data, "token": token})
        mk = MakeRestApiCall()
        logger.info(url)
        response = mk.make_request(endpoint=url, json_data=body, method='POST',
                                   headers={'content-type': 'application/json'})
        if response.get('Error'):
            message = response.get('Error')
            logger.error(message)
            return web.BadRequest(message=message)
        logger.info(response)
        return json.dumps({"message": "successfully submitted"})


class AgentBridgeApplication(web.application):
    def run(self, hostname, port=10449, *middleware):
        func = self.wsgifunc(*middleware)
        web.config.debug = eval(config['SERVER']['debug'])
        return web.httpserver.runsimple(func, (hostname, port))

    def stop(self):
        check_call(['pkill', '-f', 'rest_controller.py'])
        logger.info("web application stopped")
        exit(0)

    def is_running(self, port):
        try:
            pid = subprocess.check_output(['/usr/sbin/lsof', '-titcp:{}'.format(port)])
            return True
        except subprocess.CalledProcessError:
            pass
        return False


def add_global_hook(conn_config):
    g = web.storage({"conn_config": conn_config})

    def _wrapper(handler):
        web.ctx.globals = g
        return handler()

    return _wrapper


def main():
    if len(sys.argv) <= 1:
        print('**** Parameter Required - <start/stop/status> ****')
        quit()

    status_arg = str(sys.argv[1]).lower()
    hostname_arg = str(sys.argv[2]).lower()
    conn_config = json.loads(sys.argv[3])
    if status_arg not in ['start', 'stop', 'status']:
        quit()
    port = int(conn_config.get('port', PORT))
    if status_arg == 'start':
        ssl_cert = config['CERTS']['SSL_CRT_PATH']
        ssl_key = config['CERTS']['SSL_KEY_PATH']
        with open(ssl_cert, 'w') as f:
            f.write(conn_config.get('ssl_cert'))
        with open(ssl_key, 'w') as f:
            f.write(conn_config.get('ssl_key'))
        logger.info("Starting web application")
        app = AgentBridgeApplication(urls, globals())

        # https://groups.google.com/g/webpy/c/8RnJXiJj9Ro
        # Add Global Params to be shared across REST Controllers in web.py
        app.add_processor(add_global_hook(conn_config))
        HTTPServer.ssl_adapter = BuiltinSSLAdapter(
            certificate=ssl_cert,
            private_key=ssl_key)
        app.run(hostname_arg, port=port)
    elif status_arg == 'stop':
        AgentBridgeApplication().stop()
    elif status_arg == 'status':
        return AgentBridgeApplication().is_running(port)


if __name__ == "__main__":
    print(main())
