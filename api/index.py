"""refresh share token and pool token"""

# from os import getenv
from datetime import datetime, timedelta
import time
from urllib.parse import urlparse
from os import getenv
import json
from flask import Flask, request
import requests
import redis
import jwt
import telebot

TIME_OUT = 60
T_FORMAT = '%Y-%m-%dT%H:%M:%SZ'

R_PK = 'pk'
R_PK_FKS = 'pk_fks'
R_REFRESH_PK = 'refresh_pk'

redis_url = getenv('KV_URL', '')
api_auth = getenv('API_AUTH_KEY', '')
open_ai_accounts = getenv('OPEN_AI_ACCOUNTS', '')
fk_unique_name = getenv('FK_UNIQUE_NAME', '')
api_base_url = getenv('API_BASE_URL', '')
tg_token = getenv('TG_TOKEN', '')
tg_chat_id = getenv('TG_CHAT_ID', '')

bot = telebot.TeleBot(tg_token)
def send_tg_msg(msg):
    bot.send_message(tg_chat_id, msg)

def create_redis_from_url():
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
r = create_redis_from_url()


def register_fk(credentials_str='', unique_name=''):
    """Register fk: login and convert access token to share token"""

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

        send_tg_msg(f'Login begin: {username}, {progress}')

        token_info = {
            'username': username,
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
            auth = requests.post(
                f'{api_base_url}/api/auth/login', data={'username': username, 'password': password}, timeout=TIME_OUT)
            
            token_info['token'] = auth['access_token']
            access_token_exp = jwt.decode(auth['access_token'], options={"verify_signature": False})['exp']
            token_info['expires'] = access_token_exp.strftime(T_FORMAT)

            send_tg_msg(f'{username} Login success: {progress}')
            # delay 10 seconds to avoid too many requests
            time.sleep(10)
        except Exception as auth_error:
            err_str = str(auth_error).replace(
                '\n', '').replace('\r', '').strip()
            token_info['auth_error'] = err_str

            send_tg_msg(f'{username} Login failed: {err_str}')
            continue

        data = {
            'unique_name': unique_name,
            'access_token': token_info['token'],
            # share token expires in seconds
            'expires_in': 0,
        }
        resp = requests.post(
            f'{api_base_url}/api/token/register', data=data, timeout=TIME_OUT)

        if resp.status_code == 200:
            token_info['share_token'] = resp.json()['token_key']
            send_tg_msg(f'share token success: {username}')
        else:
            err_str = resp.text.replace('\n', '').replace('\r', '').strip()
            send_tg_msg(f'share token failed: {err_str}')
            token_info['share_token_error'] = err_str
            continue
    return token_infos


def register_pk_with_fks(fks, old_pk=None):
    """Register pool token with share tokens"""
    send_tg_msg('Begin combine token_infos')

    data = {'share_tokens': '\n'.join(fks)}
    if old_pk is not None:
        data['pool_token'] = old_pk
    resp = requests.post(
        f'{api_base_url}/api/pool/update', data=data, timeout=TIME_OUT)

    pk_info = {
        'pool_token': 'None',
        'timestamp': datetime.utcnow().strftime(T_FORMAT),
        'error': 'None'
    }

    if resp.status_code == 200:
        pk_info['pool_token'] = resp.json()['pool_token']
        send_tg_msg('Register pool token success')
    else:
        pk_info['error'] = resp.text
        send_tg_msg(f'Generate pool token failed: {pk_info["error"]}')
    return pk_info


def register_pk(credentials_str='', unique_name='', old_pk=None):
    """Register pks and then combine them to pk"""

    token_infos = register_fk(credentials_str, unique_name)
    # remove token field from item in token_infos
    stored_infos = [dict(token_info, token=None) for token_info in token_infos]
    # save token infos to redis no matter success or not
    r.hset(R_PK_FKS, 'items', json.dumps(stored_infos))

    fks = [token_info['share_token']
           for token_info in token_infos if token_info['share_token'] != 'None']

    # 如果你只是要刷新Share Token，本函数余下部分不需要。
    if len(fks) == 0:
        send_tg_msg(f'token_infos list is incomplete {len(fks)}/{len(token_infos)}.')
        return

    pk_info = register_pk_with_fks(fks, old_pk)
    pk_info['expires'] = token_infos[0]['expires']
    # save pool token to redis
    r.hset(R_PK, mapping=pk_info)


def refresh_pool_token():
    """Refresh pool token: combine some fks to a pool token"""
    # check if pool token is expired
    pool_token_expires = r.hget(R_PK, 'expires')
    if pool_token_expires is None or (datetime.utcnow() + timedelta(hours=2)) > \
            datetime.strptime(pool_token_expires.decode(), T_FORMAT):
        register_pk(open_ai_accounts,
                    fk_unique_name,
                    r.hget(R_PK, 'pool_token').decode())
        return 'pk is empty or expired.'
    return 'pk is not expired.'


# Flask app
app = Flask(__name__)


@app.route('/refresh_pk')
def refresh_pool_key():
    """Refresh pool key"""
    # validate authorization in header
    auth = request.headers.get('Authorization')
    if auth is None or auth != api_auth:
        return 'Unauthorized', 401

    refresh_record = {'timestamp': datetime.utcnow().strftime(
        T_FORMAT), 'error': 'None', 'result': 'None'}

    # pylint: disable=broad-except
    try:
        if request.headers.get('X-Refresh-H') is None:
            refresh_record['result'] = refresh_pool_token()
            return refresh_record['result'], 200

        register_pk(open_ai_accounts, 
                    fk_unique_name, 
                    r.hget(R_PK, 'pool_token').decode())
        refresh_record['result'] = 'force to refresh.'
        return refresh_record['result'], 200
    except Exception as run_error:
        refresh_record['error'] = str(run_error)
        return str(run_error), 500
    finally:
        r.hset(R_REFRESH_PK, mapping=refresh_record)


# app.run(port=3000)
