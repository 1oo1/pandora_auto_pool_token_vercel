"""refresh share token and pool token"""

# from os import getenv
from datetime import datetime, timedelta
from urllib.parse import urlparse
from os import getenv
import json
from flask import Flask
from pandora.openai.auth import Auth0
import requests
import redis

TIME_OUT = 60
T_FORMAT = '%Y-%m-%dT%H:%M:%SZ'

R_PK = 'pk'
R_PK_FKS = 'pk_fks'


def create_redis_from_url(redis_url):
    """Create a Redis client object from a URL."""
    # Parse the URL
    url = urlparse(redis_url)

    # Extract the components
    host = url.hostname
    port = url.port
    username = url.username
    password = url.password
    ssl = True

    # Create and return the Redis object
    return redis.Redis(host=host, port=port, username=username, password=password, ssl=ssl)


# init redis
r = create_redis_from_url(getenv('KV_URL', ''))


def refresh_fk(credentials_str='', unique_name=''):
    """Refresh fk: login and convert access token to share token"""

    # split with ; to get multiple credentials
    credentials = credentials_str.split(';')
    credentials = [credential.split(',', 1) for credential in credentials]

    count = 0
    token_infos = []
    for credential in credentials:
        progress = f'{credentials.index(credential) + 1}/{len(credentials)}'
        if not credential or len(credential) != 2:
            continue

        count += 1
        username, password = credential[0].strip(), credential[1].strip()

        print(f'Login begin: {username}, {progress}')

        token_info = {
            username: username,
            'timestamp': datetime.utcnow().strftime(T_FORMAT),
            'token': 'None',
            'share_token': 'None',
            'expires': 'None',
            'auth_error': 'None',
            'share_token_error': 'None',
        }
        token_infos.append(token_info)

        # pylint: disable=broad-except
        try:
            auth = Auth0(username, password)
            token_info['token'] = auth.auth(True)
            token_info['expires'] = auth.expires.strftime(T_FORMAT)

            print(f'Login success: {username}, {progress}')
        except Exception as auth_error:
            err_str = str(auth_error).replace(
                '\n', '').replace('\r', '').strip()
            token_info['auth_error'] = err_str

            print(f'{username} Login failed: {err_str}')
            continue

        data = {
            'unique_name': unique_name,
            'access_token': token_info['token'],
            # share token expires in seconds
            'expires_in': 0,
        }
        resp = requests.post(
            'https://ai.fakeopen.com/token/register', data=data, timeout=TIME_OUT)

        if resp.status_code == 200:
            token_info['share_token'] = resp.json()['token_key']
            print(f'share token success: {username}')
        else:
            err_str = resp.text.replace('\n', '').replace('\r', '').strip()
            print(f'share token failed: {err_str}'.format(err_str))
            token_info['share_token_error'] = err_str
            continue
    return token_infos


def refresh_pk(credentials_str='', unique_name=''):
    """Refresh pool token"""

    token_infos = refresh_fk(credentials_str, unique_name)
    # save token infos to redis
    r.hset(R_PK_FKS, 'items', json.dumps(token_infos))

    fks = [token_info['share_token']
           for token_info in token_infos if token_info['share_token'] != 'None']

    # 如果你只是要刷新Share Token，本函数余下部分不需要。
    if len(fks) == 0:
        print(f'token_infos list is incomplete {len(fks)}/{len(token_infos)}.')
        return

    print(f'Begin combine token_infos: {token_infos}')

    data = {'share_tokens': '\n'.join(fks)}
    resp = requests.post(
        'https://ai.fakeopen.com/pool/update', data=data, timeout=TIME_OUT)

    pk_info = {
        'pool_token': 'None',
        'timestamp': datetime.utcnow().strftime(T_FORMAT),
        'expires': token_infos[0]['expires'],
        'error': 'None'
    }

    if resp.status_code == 200:
        pk_info['pool_token'] = resp.json()['pool_token']
        print('Register pool token success')
    else:
        pk_info['error'] = resp.text
        print(f'generate pool token failed: {pk_info["error"]}')

    # save pool token to redis
    r.hset(R_PK, mapping=pk_info)


def refresh_pool_token():
    """Refresh pool token: combine some fks to a pool token"""
      # check if pool token is expired
    pool_token_expires = r.hget(R_PK, 'expires')
    if pool_token_expires is None or (datetime.utcnow() - timedelta(hours=2)) > datetime.strptime(pool_token_expires.decode(), T_FORMAT):
        refresh_pk(getenv('OPEN_AI_ACCOUNTS', ''),
                    getenv('DING_UNIQUE_NAME', ''))
        return 'expired'
    else:
        return 'not expired'


# Flask app
app = Flask(__name__)

@app.route('/refresh_token')
def home():
    """Refresh token"""
    # pylint: disable=broad-except
    try:
        return refresh_pool_token()
    except Exception as run_error:
        return str(run_error), 500


@app.route('/<path:path>')
def catch_all():
    """Catch all other path to return 404"""
    return '404', 404


# app.run(port=3000)
