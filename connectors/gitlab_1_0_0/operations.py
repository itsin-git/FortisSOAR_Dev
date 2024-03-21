import requests
import base64
import json
from connectors.core.connector import get_logger, ConnectorError

logger = get_logger('gitlab')


class GitLab:
    def __init__(self, config):
        self.server_url = config.get('server_url')
        if not self.server_url.startswith('https://'):
            self.server_url = 'https://' + self.server_url
        self.server_url.strip('/')
        self.api_key = config.get('api_key')
        self.verify_ssl = config.get('verify_ssl')

    def make_request(self, endpoint, method='get', data=None, params=None, files=None):
        try:
            url = self.server_url + endpoint
            logger.info('Executing url {}'.format(url))
            headers = {'PRIVATE-TOKEN': self.api_key, 'Content-Type': 'application/json', 'Accept': 'application/json'}
            response = requests.request(method, url, params=params, files=files, data=data, headers=headers,
                                        verify=self.verify_ssl)
            if response.ok:
                logger.info('successfully get response for url {}'.format(url))
                if method == 'delete':
                    return response
                else:
                    return response.json()
            elif response.status_code == 400:
                error_response = response.json()
                error_description = error_response['message']
                raise ConnectorError({'error_description': error_description})
            elif response.status_code == 401:
                error_response = response.json()
                if error_response.get('error'):
                    error_description = error_response['error']
                else:
                    error_description = error_response['message']
                raise ConnectorError({'error_description': error_description})
            elif response.status_code == 404:
                error_response = response.json()
                error_description = error_response['message']
                raise ConnectorError({'error_description': error_description})
            else:
                logger.error(response.json())
        except requests.exceptions.SSLError:
            raise ConnectorError('SSL certificate validation failed')
        except requests.exceptions.ConnectTimeout:
            raise ConnectorError('The request timed out while trying to connect to the server')
        except requests.exceptions.ReadTimeout:
            raise ConnectorError('The server did not send any data in the allotted amount of time')
        except requests.exceptions.ConnectionError:
            raise ConnectorError('Invalid endpoint or credentials')
        except Exception as err:
            raise ConnectorError(str(err))
        raise ConnectorError(response.text)


def get_file_from_repository(config, params):
    try:
        tg = GitLab(config)
        file_path = params.get('file_path')
        ref = params.get('ref')
        project_id = params.get('project_id')
        endpoint = '/api/v4/projects/' + str(project_id) + '/repository/files/' + file_path
        data = {'ref': ref}
        return tg.make_request(endpoint=endpoint, params=params, data=json.dumps(data))
    except Exception as err:
        logger.error(str(err))
        raise ConnectorError(str(err))


def update_file_in_repository(config, params):
    try:
        tg = GitLab(config)
        file_path = params.get('file_path')
        branch = params.get('branch')
        project_id = params.get('project_id')
        existing_content = get_file_from_repository(config, params={'file_path': file_path, 'ref': branch,
                                                                    'project_id': project_id})
        content = str(base64.b64decode(existing_content.get('content')), 'utf-8') + '\n' + params.get('content')
        commit_message = params.get('commit_message')
        data = {'branch': branch, 'content': content, 'commit_message': commit_message}
        endpoint = '/api/v4/projects/' + str(project_id) + '/repository/files/' + file_path
        return tg.make_request(endpoint=endpoint, method='put', data=json.dumps(data))
    except Exception as err:
        logger.error(str(err))
        raise ConnectorError(str(err))


def create_new_file_in_repository(config, params):
    try:
        tg = GitLab(config)
        project_id = params.get('project_id')
        file_path = params.get('file_path')
        branch = params.get('branch')
        content = params.get('content')
        commit_message = params.get('commit_message')
        author_email = params.get('author_email')
        if author_email is None:
            author_email = ''
        author_name = params.get('author_name')
        if author_name is None:
            author_name = ''
        data = {'branch': branch, 'content': content, 'commit_message': commit_message, 'author_email': author_email,
                'author_name': author_name}
        endpoint = '/api/v4/projects/' + str(project_id) + '/repository/files/' + file_path
        return tg.make_request(endpoint=endpoint, method='post', data=json.dumps(data))
    except Exception as err:
        logger.error(str(err))
        raise ConnectorError(str(err))


def delete_existing_file_in_repository(config, params):
    try:
        tg = GitLab(config)
        project_id = params.get('project_id')
        file_path = params.get('file_path')
        branch = params.get('branch')
        commit_message = params.get('commit_message')
        author_email = params.get('author_email')
        if author_email is None:
            author_email = ''
        author_name = params.get('author_name')
        if author_name is None:
            author_name = ''
        data = {'branch': branch, 'commit_message': commit_message, 'author_email': author_email,
                'author_name': author_name}
        endpoint = '/api/v4/projects/' + str(project_id) + '/repository/files/' + file_path
        return tg.make_request(endpoint=endpoint, method='delete', data=json.dumps(data))
    except Exception as err:
        logger.error(str(err))
        raise ConnectorError(str(err))


def _check_health(config):
    try:
        tg = GitLab(config)
        endpoint = '/api/v4/projects'
        response = tg.make_request(endpoint=endpoint)
        if response:
            logger.info("GitLab Connector Available")
            return True
    except Exception as err:
        logger.error(str(err))
        raise ConnectorError(str(err))


operations = {
    'get_file_from_repository': get_file_from_repository,
    'update_file_in_repository': update_file_in_repository,
    'create_new_file_in_repository': create_new_file_in_repository,
    'delete_existing_file_in_repository': delete_existing_file_in_repository

}
