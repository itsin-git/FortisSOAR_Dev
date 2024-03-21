import json
import subprocess
import sys
from subprocess import check_call

import web
import server

from ml_utils import log
from ml_utils.config import config
logger = log.get_logger(__name__)

PORT = config['SERVER']['port']

urls = (
    '/classifier', 'RestController'
)

process_name = 'rest_controller.py'


class RestController:
    def GET(self):
        return "get"

    def POST(self):
        logger.debug(f"payload received in request\n {web.data()}")
        body = json.loads(web.data())
        action = body["action"]
        data = body["data"]
        web.header('Content-Type', 'application/json')
        try:
            if action == "train":
                logger.debug("train action received")
                training_results = server.train(data)
                return json.dumps(training_results.__dict__)
            elif action == "predict":
                logger.debug("predict action received")
                prediction_results = server.predict(data)
                return json.dumps(prediction_results.__dict__)
            elif action == "check-health":
                logger.debug("check health action received")
                return json.dumps(server.check_health(data))
            elif action == "untrain":
                logger.debug("untrain action received")
                return json.dumps(server.untrain(data))
            elif action == "cleanup":
                logger.debug("cleanup action received")
                return json.dumps(server.cleanup(data))
            elif action == "get_training_results":
                logger.debug("Request received to get training results")
                training_results = server.get_training_results(data)
                return json.dumps(training_results.__dict__)
            elif action == "mark_stale":
                logger.debug("Request received to mark configuration stale")
                return json.dumps(server.mark_trained_data_stale(data))
        except Exception as error:
            logger.error(error, exc_info=True)
            raise web.internalerror(f"Failed to perform operation {action}, check logs")


class MyApplication(web.application):
    def run(self, port=10449, *middleware):

        func = self.wsgifunc(*middleware)
        return web.httpserver.runsimple(func, ('localhost', port))

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


def main():
    if len(sys.argv) <= 1:
        print( '**** Parameter Required - <start/stop/status> ****')
        quit()

    arg = str(sys.argv[1]).lower()
    if arg not in ['start', 'stop', 'status']:
        quit()

    if arg == 'start':
        logger.info("Starting web application")
        MyApplication(urls, globals()).run(port=int(PORT))
    elif arg == 'stop':
        MyApplication().stop()
    elif arg == 'status':
        return MyApplication().is_running(PORT)


if __name__ == "__main__":
    print(main())