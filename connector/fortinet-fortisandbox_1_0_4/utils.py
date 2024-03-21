""" Copyright start
  Copyright (C) 2008 - 2021 Fortinet Inc.
  All rights reserved.
  FORTINET CONFIDENTIAL & FORTINET PROPRIETARY SOURCE CODE
  Copyright end """
import requests
from base64 import b64encode
from connectors.core.connector import get_logger, ConnectorError


logger = get_logger('fortisandbox')


QUERY_SCHEMA = {
    'login': {
        'method': 'exec',
        'params': [
            {
                'url': '/sys/login/user',
                'data': []
            }
        ],
        'id': 1,
        'ver': '2.1'
    },
    'logout': {
        'method': 'exec',
        'params': [{'url': '/sys/logout'}],
        'session': '',
        'id': 2,
        'ver': '2.1'
    },
    'get_status': {
        'method': 'get',
        'params': [{'url': '/sys/status'}],
        'session': '',
        'id': 3,
        'ver': '2.1'
    },
    'get_scan_stats': {
        'method': 'get',
        'params': [
            {
                'url': '/scan/stat/last_7day',
                'period': 7*24*60
            }
        ],
        'session': '',
        'id': 8,
        'ver': '2.1'
    },
    'get_job_verdict': {
        'method': 'get',
        'params': [
            {
                'url': '/scan/result/job',
                'jid': ''
            }
        ],
        'session': '',
        'id': 10,
        'ver': '2.1'
    },
    'get_file_rating': {
        'method': 'get',
        'params': [
            {
                'url': '/scan/result/filerating',
                'checksum': '',
                'ctype': ''
            }
        ],
        'session': '',
        'id': 13,
        'ver': '2.1'
    },
    'file_upload': {
        'method': 'set',
        'params': [
            {
                'file': '',
                'filename': '',
                # 'skip_steps': '1,2,4',
                'url': '/alert/ondemand/submit-file',
                'type': 'file',
                'overwrite_vm_list': ''
            }
        ],
        'session': '',
        'id': 11,
        'ver': '2.1'
    },
    'file_upload_url': {
        'method': 'set',
        'params': [
            {
                'file': '',
                'filename': '',
                'url': '/alert/ondemand/submit-file',
                'timeout': '60',
                'depth': '1',
                'overwrite_vm_list': '',
                'type': 'url'
            }
        ],
        'session': '',
        'id': 12,
        'ver': '2.1'
    },
    'get_url_rating': {
        'method': 'get',
        'params': [
            {
                'url': '/scan/result/urlrating',
                'address': ''
            }
        ],
        'session': '',
        'id': 14,
        'ver': '2.1'
    },
    'cancel-submission': {
        'method': 'exec',
        'params': [
            {
                'url': '/alert/ondemand/cancel-submssion',
                'sid': '',
                'reason': ''
            }
        ],
        'session': '',
        'id': 16,
        'ver': '2.0'
    },
    'get_file_verdict': {
        'method': 'get',
        'params': [
            {
                'url': '/scan/result/file',
                'checksum': '',
                'ctype': ''
            }
        ],
        'session': '',
        'id': 10,
        'ver': '2.1'
    },
    'get-jobs-of-submission': {
        'method': 'get',
        'params': [
            {
                'url': '/scan/result/get-jobs-of-submission',
                'sid': '',
            }
        ],
        'session': '',
        'id': 17,
        'ver': '2.1'
    },
    'get-job-behavior': {
        'method': 'get',
        'params': [
            {
                'url': '/scan/result/get-job-behavior',
                'checksum': '',
                'ctype': ''
            }
        ],
        'session': '',
        'id': 18,
        'ver': '2.1'
    },
    'white-black-list': {
      "method": "post",
      "params": [
        {
          "url": "/scan/policy/black-white-list",
          "list_type": "",
          "checksum_type": "",
          "action": "",
          "upload_file": ""
        }
      ],
      "session": "",
      "id": 25,
      "ver": "2.2.1"
    },
    'mark-sample-fp-fn':
        {
            "method": "post",
            "params": [
                {
                  "url": "/analysis/details/submit-feedback",
                  "jid": "",
                  "comments": "",
                  "cloud_submit": 0
                }
            ],
            "session": "",
            "id": 26,
            "ver": "2.3"
        },
    'get-avrescan':
        {
          "method": "post",
          "params": [
            {
              "url": "/scan/result/get-avrescan",
              "need_av_ver": 0,
              "stime": '',
              "etime": ''
            }
          ],
          "session": "",
          "id": 23,
          "ver": "2.1"
        },
    'get-multiple-file-verdict':
        {
          "method": "get",
          "params": [
            {
              "url": "/scan/result/multifile",
              "ctype": "",
              "checksum": []
            }
          ],
          "session": "",
          "id": 43,
          "ver": "2.4"
        },
    'get-all-installed-vm':
        {
        "method": "get",
        "params": [
            {
              "url": "/alert/ondemand/hcmvminfo"
            }
        ],
        "session": "",
        "id": 43,
        "ver": "2.4"
        },
    'get-pdf-report':
        {
          "method": "get",
          "params": [
            {
              "url": "/scan/result/get-pdf-report",
              "qtype": "",
              "qval": ""
            }
          ],
          "session": "",
          "id": 50,
          "ver": "2.5"
        },

    'download-malpkg':
        {
          "method": "post",
          "params": [
            {
              "url": "/scan/device/download-malpkg-text",
              "type": 0,
              # "lazy": 1,
              # "minor": 100,
              # "major": 2
            }
          ],
          "session": "",
          "id": 22,
          "ver": "2.4.1"
        },


    'get_dev_settings': {
        'method': 'get',
        'params': [{'url': '/config/scan/devsniffer',}],
        'session': '',
        'id': 4,
        'ver': '2.1'
    },
    'get_option_settings': {
        'method': 'get',
        'params': [{'url': '/config/scan/options',}],
        'session': '',
        'id': 5,
        'ver': '2.1'
    },
    'set_dev_settings':  {
        'method': 'set',
        'params': [
            {
                'url': '/config/scan/devsniffer',
                'data': [
                    {
                        'sniffer': 0,
                        'sniffer_port': 'port2,port4',
                        'callback_detection': 1,
                        'keep_incomplete_file': 1,
                        'max_file_size': 2048,

                    }
                ]
            }
        ],
        'session': '',
        'id': 6,
        'ver': '2.1'
    },
    'set_option_settings': {
        'method': 'set',
        'params': [
            {
                'url': '/config/scan/options',
                'data': [
                    {
                        'cloud_upload': 0,
                        'vm_network_access': 1,
                        'log_device_submission': 1,
                        'rej_dup_device_submission': 1,
                        'del_clean_file': 20160,
                        'del_job_info': 20160
                    }
                ]
            }
        ],
        'session': '',
        'id': 7,
        'ver': '2.1'
    },
    'get_backup_file': {
        'method': 'exec',
        'params': [{'url': '/backup/config',}],
        'session': '',
        'id': 9,
        'ver': '2.1'
    },
}


class FortiSandbox:
    def __init__(self, config):
        self.base_url = config.get('server').strip('/') + '/jsonrpc'
        if not self.base_url.startswith('https://'):
            self.base_url = 'https://{0}'.format(self.base_url)
        self.username = config['username']
        self.password = config['password']
        self.verify_ssl = config['verify_ssl']
        self.error_msg = {
            400: 'Bad/Invalid Request',
            401: 'Invalid credentials were provided',
            403: 'Access Denied',
            402: 'API Search quota is exceeded',
            500: 'Internal Server Error',
            503: 'Service Unavailable',
            'time_out': 'The request timed out while trying to connect to the remote server',
            'ssl_error': 'SSL certificate validation failed'
        }
        self.session_id = self.login()

    def _load_file_for_upload(self, content, test_input, filename):
        """
        Load file contents into input mapping.
        @type test_input: dict
        @param test_input: JSON RPC request data.
        @type filename: basestring
        @param filename: filename override optional param.
        @rtype: dict
        @return: updated JSON RPC request dict.
         """
        base64_data = b64encode(content).decode() if isinstance(content, bytes) else b64encode(content.encode()).decode()
        test_input['params'][0]['file'] = base64_data
        test_input['params'][0]['filename'] = b64encode(filename.encode()).decode()
        return test_input

    def _handle_post(self, data):
        """
        POST JSON RPC request..

        @type post_url: basestring
        @param post_url: URL to server running RPC code.
        @type data: dict
        @param data: JSON RPC request data.
        @rtype: HttpResponse
        @return: JSON RPC response data.
        """

        try:
            response = requests.post(self.base_url, json=data, verify=self.verify_ssl)
            if response.ok:
                return response.json()
            if self.error_msg[response.status_code]:
                raise ConnectorError('{}'.format(self.error_msg[response.status_code]))
            response.raise_for_status()

        except requests.exceptions.SSLError as e:
            logger.exception(e)
            raise ConnectorError(self.error_msg['ssl_error'])
        except requests.exceptions.ConnectionError as e:
            logger.exception(e)
            raise ConnectorError(self.error_msg['time_out'])
        except Exception as err:
            logger.exception(err)
            raise ConnectorError(err)

    def login(self):
        try:
            login_input = QUERY_SCHEMA.get('login')
            login_input['params'][0]['data'] = [{'user': self.username, 'passwd': self.password}]
            login_response = self._handle_post(login_input)
            if 'session' in login_response:
                logger.info('Logged in successfully')
                return login_response['session']
            else:
                logger.error('SessionID is not available')
                raise ConnectorError(login_response['result']['status'])
        except Exception as e:
            raise ConnectorError(e)

    def logout(self):
        try:
            logout_input = QUERY_SCHEMA.get('logout')
            logout_input['session'] = self.session_id
            self._handle_post(logout_input)
            logger.info('Logged out successfully')
        except Exception as e:
            raise ConnectorError(e)

