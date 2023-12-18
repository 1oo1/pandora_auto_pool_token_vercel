import redis
from os import getenv
from urllib.parse import urlparse

redis_url = getenv('KV_URL', '')

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

def save_session_token(session_token, username):
    r.hset('session_tokens', username, session_token)

def get_session_token(username):
    return r.hget('session_tokens', username)


def save_access_token(access_token, username):
    r.hset('access_tokens', username, access_token)

def get_access_token(username):
    return r.hget('access_tokens', username)


def save_share_token(share_token, username):
    r.hset('share_tokens', username, share_token)

def get_share_token(username):
    return r.hget('share_tokens', username)


def save_pool_token(pk, exp):
    value = {'pk': pk, 'exp': exp}
    r.hset('pool_token', mapping=value)

def get_pool_token():
    if r.exists('pool_token') == 0:
        return None
    return r.hget('pool_token', 'pk')

def get_pool_token_exp():
    if r.exists('pool_token') == 0:
        return None
    return r.hget('pool_token', 'exp')