""" Copyright start
  Copyright (C) 2008 - 2023 Fortinet Inc.
  All rights reserved.
  FORTINET CONFIDENTIAL & FORTINET PROPRIETARY SOURCE CODE
  Copyright end """

import json
from requests.auth import HTTPBasicAuth
from requests import request, exceptions as req_exceptions
from connectors.core.connector import get_logger, ConnectorError
from .constants import *
from integrations.crudhub import make_request

logger = get_logger('trend-micro-sms')


def _get_config(config):
    verify_ssl = config.get("verify_ssl", None)
    port = config.get("port")
    url = config.get('host').strip('/')
    if not url.startswith('https://') and not url.startswith('http://'):
        if port:
            server_url = 'https://{0}:{1}'.format(url, port)
        else:
            server_url = 'https://{0}'.format(url)
    else:
        if port:
            server_url = url + ':{0}'.format(port)
        else:
            server_url = url
    return server_url, verify_ssl


def make_rest_call(endpoint, config, files=None, data=None, params=None, method='GET'):
    credentials = None
    server_url, verify_ssl = _get_config(config)
    url = '{0}/{1}'.format(server_url, endpoint)
    headers = {"Content-Type": "application/json"}
    auth_type = config.get('authentication_type')
    if auth_type == 'Basic Auth':
        credentials = HTTPBasicAuth(config.get('smsuser'), config.get('smspass'))
    elif auth_type == 'API Key':
        headers.update({'X-SMS-API-KEY': config.get('api_key')})

    try:
        response = request(method, url, data=json.dumps(data) if data else data, auth=credentials,
                           headers=headers, params=params, files=files, verify=verify_ssl)

        if response.ok:
            logger.info('Successfully got response for url {0}'.format(url))
            if 'json' in str(response.headers):
                return response.json()
            else:
                logger.info("Unable to parse response as a JSON : {text}'".format(text=response.text))
                return response.content
        else:
            logger.error(response.content)
            raise ConnectorError(
                {'status_code': response.status_code, 'message': response.content})
    except req_exceptions.SSLError as err:
        logger.error('An SSL error occurred, {}'.format(err))
        raise ConnectorError('An SSL error occurred')
    except req_exceptions.ConnectionError as err:
        logger.error('A connection error occurred, {}'.format(err))
        raise ConnectorError('Invalid endpoint or credentials')
    except req_exceptions.Timeout as err:
        logger.error('The request timed out, {}'.format(err))
        raise ConnectorError('The request timed out')
    except req_exceptions.RequestException as err:
        logger.error('There was an error while handling the request, {}'.format(err))
        raise ConnectorError('There was an error while handling the request')
    except Exception as err:
        logger.exception(err)
        raise ConnectorError(err)


def check_payload(payload):
    updated_payload = {}
    for key, value in payload.items():
        if isinstance(value, dict):
            nested = check_payload(value)
            if len(nested.keys()) > 0:
                updated_payload[key] = nested
        elif value != '' and value is not None:
            updated_payload[key] = value
    return updated_payload


def import_reputation_bulk(config, params):
    try:
        type = PARAM_MAPPING.get(params.get('address_type'), "IPv4")
        file_path = params.get('input_file')
        data = make_request(file_path.get('@id'), 'GET')
        logger.info(data)
        files = {
            'file': data
        }
        response = make_rest_call('repEntries/import&type={}'.format(type), config, files=files, method='POST')
        return response
    except Exception as err:
        logger.exception(str(err))
        raise ConnectorError(str(err))


def add_reputation_entry(config, params):
    try:
        address_type = PARAM_MAPPING.get(params.get('address_type'), "IPv4")
        address_value = params.get('address_value')
        tag_data = params.get('tag_data')
        param = {
            address_type: address_value,
            "TagData": tag_data.encode()
        }
        param = check_payload(param)
        response = make_rest_call('repEntries/add', config, params=param, method='POST')
        return response
    except Exception as err:
        logger.exception(str(err))
        raise ConnectorError(str(err))


def build_url(address_type, lst):
    try:
        if type(lst) == str:
            lst = [lst]
        return_str = ''
        for i in lst:
            return_str = return_str + '&' + address_type + '=' + i
        return return_str
    except Exception as err:
        logger.exception(str(err))
        raise ConnectorError(str(err))


def delete_reputation_entry(config, params):
    try:
        ip_list = params.get('ip_list', [])
        dns_list = params.get('dns_list', [])
        url_list = params.get('url_list', [])
        criteria = PARAM_MAPPING.get(params.get('criteria', 'ENTRY'), '')
        if ip_list == [] and dns_list == [] and url_list == [] and criteria == '':
            logger.error('At least one parameter is required')
            raise ConnectorError('At least one parameter is required')
        if ip_list == [] and dns_list == [] and url_list == [] and criteria == 'ENTRY':
            logger.error(
                'When you choose criteria as "ENTRY", At least one parameter is required from "List OF IPs", "List OF URLs or "List OF DNS')
            raise ConnectorError(
                'When you choose criteria as "ENTRY", At least one parameter is required from "List OF IPs", "List OF URLs or "List OF DNS')
        if criteria:
            param = {
                'criteria': criteria
            }
        else:
            param = {}
        ip_str = build_url('ip', ip_list)
        dns_str = build_url('dns', dns_list)
        url_str = build_url('url', url_list)
        endpoint = 'repEntries/delete' + ip_str + dns_str + url_str
        param = check_payload(param)
        response = make_rest_call(endpoint, config, params=param, method='POST')
        return response
    except Exception as err:
        logger.exception(str(err))
        raise ConnectorError(str(err))


def delete_reputation_bulk(config, params):
    try:
        param = {
            "type": PARAM_MAPPING.get(params.get('address_type'), "IPv4")
        }
        file_path = params.get('input_file')
        data = make_request(file_path.get('@id'), 'GET')
        logger.info(data)
        files = {
            'file': data
        }
        logger.info(files)
        param = check_payload(param)
        response = make_rest_call('repEntries/delete', config, files=files, params=param, method='POST')
        return response
    except Exception as err:
        logger.exception(str(err))
        raise ConnectorError(str(err))


def query_reputation_entry(config, params):
    try:
        address_type = PARAM_MAPPING.get(params.get('address_type'), "IP")
        address_value = params.get('address_value')
        endpoint = 'repEntries/query{}'.format(build_url(address_type, address_value))
        response = make_rest_call(endpoint, config, method='POST')
        return response
    except Exception as err:
        logger.exception(str(err))
        raise ConnectorError(str(err))


def quarantine_ip(config, params):
    try:
        endpoint = 'quarantine/quarantine?ip={0}'.format(params.get('ip'))
        param = {
            'policy': params.get('policy_name'),
            'timeout': params.get('timeout')
        }
        param = check_payload(param)
        response = make_rest_call(endpoint, config, params=param, method='POST')
        return response
    except Exception as err:
        logger.exception(str(err))
        raise ConnectorError(str(err))


def unquarantine_ip(config, params):
    try:
        endpoint = 'quarantine/unquarantine?ip={0}'.format(params.get('ip'))
        param = {
            'policy': params.get('policy_name'),
            'timeout': params.get('timeout')
        }
        param = check_payload(param)
        response = make_rest_call(endpoint, config, params=param, method='POST')
        return response
    except Exception as err:
        logger.exception(str(err))
        raise ConnectorError(str(err))


def check_health(config):
    try:
        response = make_rest_call('dbAccess/tptDBServlet?method=Status', config)
        if response:
            logger.info("Check health successful.. {0}".format(response))
            return True
    except Exception as err:
        raise ConnectorError(str(err))


operations = {
    'import_reputation_bulk': import_reputation_bulk,
    'add_reputation_entry': add_reputation_entry,
    'delete_reputation_entry': delete_reputation_entry,
    'delete_reputation_bulk': delete_reputation_bulk,
    'query_reputation_entry': query_reputation_entry,
    'quarantine_ip': quarantine_ip,
    'unquarantine_ip': unquarantine_ip
}
