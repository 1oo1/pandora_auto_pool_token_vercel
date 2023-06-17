"""refresh share token and pool token"""

from os import getenv
from flask import Flask
from pandora.openai.auth import Auth0
import requests

TIME_OUT = 60

def refresh():
    """Refresh token"""
    proxy = None
    expires_in = 0
    unique_name = getenv('UNIQUE_NAME')

    # split with ; to get multiple credentials
    credentials = getenv('CREDENTIALS_STR').split(';')
    credentials = [credential.split(',', 1) for credential in credentials]

    count = 0
    token_keys = []
    for credential in credentials:
        progress = f'{credentials.index(credential) + 1}/{len(credentials)}'
        if not credential or len(credential) != 2:
            continue

        count += 1
        username, password = credential[0].strip(), credential[1].strip()
        print(f'Login begin: {username}, {progress}')

        token_info = {
            'token': 'None',
            'share_token': 'None',
        }
        token_keys.append(token_info)

        # pylint: disable=broad-except
        try:
            token_info['token'] = Auth0(username, password, proxy).auth(True)
            print(f'Login success: {username}, {progress}')
        except Exception as auth_error:
            err_str = str(auth_error).replace('\n', '').replace('\r', '').strip()
            print(f'Login failed: {username}, {err_str}')
            token_info['token'] = err_str
            continue

        data = {
            'unique_name': unique_name,
            'access_token': token_info['token'],
            'expires_in': expires_in,
        }

        resp = requests.post('https://ai.fakeopen.com/token/register', data=data, timeout=TIME_OUT)
        if resp.status_code == 200:
            token_info['share_token'] = resp.json()['token_key']
            print(f'share token: {token_info["share_token"]}')
        else:
            err_str = resp.text.replace('\n', '').replace('\r', '').strip()
            print(f'share token failed: {err_str}'.format(err_str))
            token_info['share_token'] = err_str
            continue

    for token_info in token_keys:
        print(f'{token_info["token"]}\n')
        print(f'{token_info["share_token"]}\n')

    # 如果你只是要刷新Share Token，本函数余下部分不需要。
    if count > 20:
        print('too many accounts!')
        return

    data = {
        'share_tokens': '\n'.join([token_info['share_token'] for token_info in token_keys]),
    }
    resp = requests.post('https://ai.fakeopen.com/pool/update', data=data, timeout=TIME_OUT)

    if resp.status_code == 200:
        print('pool token: {}', resp.json()['pool_token'])
    else:
        print(f'generate pool token failed: {resp.text}')


# Flask app
app = Flask(__name__)
@app.route('/refresh_token')
def home():
    """Refresh token"""
    # pylint: disable=broad-except
    try:
        refresh()
        return 'success', 200
    except Exception as run_error:
        return str(run_error), 500

@app.route('/<path:path>')
def catch_all():
    """Catch all other path to return 404"""
    return '404', 404


app.run(port=5000)
