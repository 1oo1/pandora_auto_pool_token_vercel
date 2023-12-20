from os import getenv
import requests

api_base_url = getenv('API_BASE_URL', '')

TIME_OUT = 60

def login(username, password):
    """
    Login to fk and return access token
    return {'session_token': 'xxx', 'access_token': 'xxx'}
    """
    url = f'{api_base_url}/api/auth/login'
    data = {
        'username': username,
        'password': password,
    }
    res = requests.post(url, data=data, timeout=TIME_OUT)
    if res.status_code != 200:
        raise Exception(f'Login failed: {res.status_code}')

    return res.json()

def register_fk(access_token, unique_name):
    """
    Register fk with access token
    return {'token_key': 'xxx'}
    """
    url = f'{api_base_url}/api/token/register'
    data = {
        'unique_name': unique_name,
        'access_token': access_token,
        'expires_in': 0,
        'show_conversations': True,
        'show_userinfo': True
    }
    res = requests.post(url, data=data, timeout=TIME_OUT)
    if res.status_code != 200:
        raise Exception(f'Register fk failed: {res.status_code}')
    
    return res.json()

def access_token_by_sk(session_token):
    """
    Get access token by sk
    return {'access_token': 'xxx'}
    """
    url = f'{api_base_url}/api/auth/session'
    data = {
        'session_token': session_token,
    }
    res = requests.post(url, data=data, timeout=TIME_OUT)
    if res.status_code != 200 or 'access_token' not in res.json():
        raise Exception(f'Get access token failed: {res.status_code}')
    
    return res.json()

def register_pk(fks, old_pk=None):
    """
    Register pk with share tokens
    return {'pool_token': 'xxx'}
    """
    data = {'share_tokens': '\n'.join(fks)}
    if old_pk is not None:
        data['pool_token'] = old_pk
    resp = requests.post(
        f'{api_base_url}/api/pool/update', data=data, timeout=TIME_OUT)

    if resp.status_code != 200:
        raise Exception(f'Register pk failed: {resp.status_code}')
    
    return resp.json()