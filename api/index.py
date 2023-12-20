"""refresh share token and pool token"""
import time
from datetime import datetime
from os import getenv
from flask import Flask, request
import jwt
from telebot import TeleBot
from utils.tokens import login, register_fk, access_token_by_sk, register_pk
import utils.storage as storage

tg_logs = ""

api_auth = getenv('API_AUTH_KEY', '')
open_ai_accounts = getenv('OPEN_AI_ACCOUNTS', '')
tg_token = getenv('TG_TOKEN', '')
tg_chat_id = getenv('TG_CHAT_ID', '')

def split_credentials(credentials_str=''):
    """Split credentials with ; and ,"""
    credentials = credentials_str.split(';')
    user_pwds = [credential.split(',', 1) for credential in credentials]
    return user_pwds

def get_access_token(username, password):
    """get access token"""
    global tg_logs
    # read session token from redis
    session_token = storage.get_session_token(username)
    if session_token is None:
        # login to get session token
        login_res = login(username, password)
        storage.save_session_token(login_res['session_token'], username)
        # append log to tg_logs
        tg_logs += f"Session token not found for {username}\n"
        return login_res['access_token']
    
    # get access token by session token
    try:
        access_token_res = access_token_by_sk(session_token)
        # append log to tg_logs
        tg_logs += f"Session token is valid for {username}\n"
        return access_token_res['access_token']
    except Exception as err:
        # login to get session token
        login_res = login(username, password)
        storage.save_session_token(login_res['session_token'], username)
        # append log to tg_logs
        tg_logs += f"Session token not valid for {username}. err:{err}\n"
        return login_res['access_token']

def get_fk_access_token(username, password):
    access_token = get_access_token(username, password)
    fk = register_fk(access_token, "hello_pd_next_123")['token_key']
    storage.save_share_token(fk, username)
    storage.save_access_token(access_token, username)
    # return tuple
    return (fk, access_token)
    

def refresh_tokens():
    """Refresh tokens"""
    global tg_logs
    exp_at = None
    fks = []

    # split with ; to get multiple credentials
    user_pwds = split_credentials(open_ai_accounts)
    
    for user_pwd in user_pwds:
        try:
            username = user_pwd[0]
            password = user_pwd[1]
            fk, access_token = get_fk_access_token(username, password)
            if exp_at is None:
                exp_at = jwt.decode(access_token, options={"verify_signature": False})['exp']
                
            fks.append(fk)

            # append log to tg_logs
            tg_logs += f"fk for {username} is:{fk}\n"
        except Exception as err:
            # append log to tg_logs
            tg_logs += f"Login or get fk error. Error: {err}\n"
            continue
    
    old_pk = storage.get_pool_token()
    pool_token = register_pk(fks, old_pk)['pool_token']
    if pool_token is None:
        raise Exception('Register pool token failed.')
    
    storage.save_pool_token(pool_token, exp_at)

    # append count of fks and pool_token to tg_logs
    tg_logs += f"{len(fks)}/{len(user_pwds)}fks combined pool_token:{pool_token}\n"

                

# Flask app
app = Flask(__name__)

@app.route('/refresh_pk')
def refresh():
    global tg_logs
    tg_logs = f"========== {datetime.utcnow().strftime('%Y-%m-%dT%H:%M:%SZ')} ==========\n"

    # validate authorization in header
    auth = request.headers.get('Authorization')
    if auth is None or auth != api_auth:
        return 'Unauthorized', 401

    try:
        exp = storage.get_pool_token_exp()
        # if pool token is None or timestamp is not expired, return
        if exp is not None and int(time.time()) < exp:
            tg_logs += f"Ignore refresh.\n"
            return 'Not expired', 200
        
        refresh_tokens()
        return 'Refreshed', 200
    except Exception as err:
        tg_logs += f"Refresh error: {err}\n"
        return str(err), 500
    finally:
        TeleBot(tg_token).send_message(tg_chat_id, tg_logs)

# app.run(port=3000)
