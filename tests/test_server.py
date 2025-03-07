import json
import logging
import os
import socket
import time
import urllib
import uuid

import jwt
import pytest
import requests

LOGGER = logging.getLogger(__name__)


def wait_for_socket(host, port):
    retries = 10
    exception = None
    while retries > 0:
        try:
            socket.socket().connect((host, port))
            return
        except ConnectionRefusedError as e:
            exception = e
            print(f'Got ConnectionError for url {host}:{port}: {e} , retrying')
            retries -= 1
            time.sleep(2)
    raise exception


@pytest.fixture
def auth_addr():
    addr = os.environ.get('AUTH_SERVER_URL', 'http://127.0.0.1:8090')
    host = urllib.parse.urlparse(addr).hostname
    port = urllib.parse.urlparse(addr).port
    wait_for_socket(host, port)
    yield addr


@pytest.fixture
def proxy_addr():
    addr = os.environ.get('PROXY_SERVER_URL', 'http://127.0.0.1:8091')
    host = urllib.parse.urlparse(addr).hostname
    port = urllib.parse.urlparse(addr).port
    wait_for_socket(host, port)
    yield addr


@pytest.fixture
def jwt_private():
    path = os.environ.get('JWT_PRIVATE_KEY_FILE', 'secret')
    with open(path, 'rb') as file:
        key = file.read()
    yield key


@pytest.fixture
def jwt_public():
    path = os.environ.get('JWT_PUBLIC_KEY_FILE', 'secret')
    with open(path, 'rb') as file:
        key = file.read()
    yield key


def make_requests(method, addr, handle, params=None, data=None, cookies=None):
    if data is not None:
        data = json.dumps(data)
    req = requests.Request(
        method,
        addr +
        handle,
        params=params,
        data=data,
        cookies=cookies)
    prepared = req.prepare()
    LOGGER.info(f'>>> {prepared.method} {prepared.url}')
    if len(req.data) > 0:
        LOGGER.info(f'>>> {req.data}')
    if req.cookies is not None:
        LOGGER.info(f'>>> {req.cookies}')
    s = requests.Session()
    resp = s.send(prepared)
    LOGGER.info(f'<<< {resp.status_code}')
    if len(resp.content) > 0:
        LOGGER.info(f'<<< {resp.content}')
    if len(resp.cookies) > 0:
        LOGGER.info(f'<<< {resp.cookies}')
    return resp


def make_user(auth_addr):
    username = str(uuid.uuid4())
    password = str(uuid.uuid4())
    email = f'{username}@mail.com'
    r = make_requests(
        'POST',
        auth_addr,
        '/signup',
        data={
            'username': username,
            'password': password,
            'email': email})
    assert r.status_code == 200
    cookies = r.cookies.get_dict()
    return ((username, email, password), cookies)



@pytest.fixture
def user(auth_addr):
    yield make_user(auth_addr)


def generate_jwt(private, username):
    return jwt.encode({'username': username}, private, 'RS256')


def parse_jwt(token, public):
    return jwt.decode(token, public, ['RS256'])


def generate_hs256_jwt(secret, username):
    return jwt.encode({'username': username}, secret, 'HS256')


class TestRSA:
    @staticmethod
    def test_private(jwt_private):
        generate_jwt(jwt_private, 'test')

    @staticmethod
    def test_public(jwt_private, jwt_public):
        token = generate_jwt(jwt_private, 'test')
        decoded = parse_jwt(token, jwt_public)
        assert decoded['username'] == 'test'


class TestAuth:
    @staticmethod
    def check_jwt(cookies, public, username):
        token = cookies['jwt']
        decoded = parse_jwt(token, public)
        assert decoded['username'] == username

    @staticmethod
    def test_signup(jwt_public, user):
        ((username, email, _), cookies) = user
        TestAuth.check_jwt(cookies, jwt_public, username)

    @staticmethod
    def test_signup_with_existing_user(auth_addr, user):
        ((username, email, _), _) = user
        password = str(uuid.uuid4())
        r = make_requests(
            'POST',
            auth_addr,
            '/signup',
            data={
                'username': username,
                'email': email,
                'password': password})
        assert r.status_code == 403
        assert len(r.cookies) == 0

    @staticmethod
    def test_login(auth_addr, jwt_public, user):
        ((username, _, password), _) = user
        r = make_requests(
            'POST',
            auth_addr,
            '/login',
            data={
                'username': username,
                'password': password})
        assert r.status_code == 200
        TestAuth.check_jwt(r.cookies, jwt_public, username)

    @staticmethod
    def test_login_with_wrong_password(auth_addr, user):
        ((username, _, _), _) = user
        password = str(uuid.uuid4())
        r = make_requests(
            'POST',
            auth_addr,
            '/login',
            data={
                'username': username,
                'password': password})
        assert r.status_code == 403
        assert len(r.cookies) == 0

    @staticmethod
    def test_login_with_non_existing_user(auth_addr):
        username = str(uuid.uuid4())
        password = str(uuid.uuid4())
        r = make_requests(
            'POST',
            auth_addr,
            '/login',
            data={
                'username': username,
                'password': password})
        assert r.status_code == 403
        assert len(r.cookies) == 0

    @staticmethod
    def test_whoami(auth_addr, user):
        ((username, _, _), cookies) = user
        r = make_requests('GET', auth_addr, '/whoami', cookies=cookies)
        assert r.status_code == 200
        assert r.content == f'Hello, {username}'.encode()

    @staticmethod
    def test_whoami_without_cookie(auth_addr):
        r = make_requests('GET', auth_addr, '/whoami')
        assert r.status_code == 401

    @staticmethod
    def test_whoami_with_wrong_cookie(auth_addr):
        r = make_requests(
            'GET',
            auth_addr,
            '/whoami',
            cookies={
                'jwt': 'not jwt'})
        assert r.status_code == 400

    @staticmethod
    def test_whoami_with_cookie_of_non_existing_user(auth_addr, jwt_private):
        token = generate_jwt(jwt_private, 'Bob')
        r = make_requests('GET', auth_addr, '/whoami', cookies={'jwt': token})
        assert r.status_code == 400

    @staticmethod
    def test_whoami_with_cookie_signed_by_other_secret(auth_addr):
        token = generate_hs256_jwt('wrong secret', 'Alice')
        r = make_requests('GET', auth_addr, '/whoami', cookies={'jwt': token})
        assert r.status_code == 400
    
    # @staticmethod
    # def test_update_profile(auth_addr):
    #     ((username, _), cookies) = user
    #     profile_data = {'name': 'Артемий', 
    #                     'surname': 'Новиков', 
    #                     'phone-number': '+79651234567',
    #                     'burthday': '11-09-2004',
    #                     'email': f'{username}_new@mail.com'
    #                     }
    #     r = make_requests('POST', auth_addr, '/update-profile', data=profile_data, cookies={'jwt': cookies})
    #     assert r.status_code == 200


class TestProxy:
    @staticmethod
    def check_jwt(cookies, public, username):
        token = cookies['jwt']
        decoded = parse_jwt(token, public)
        assert decoded['username'] == username

    @staticmethod
    def test_signup(jwt_public, user):
        ((username, email, _), cookies) = user
        TestAuth.check_jwt(cookies, jwt_public, username)

    @staticmethod
    def test_signup_with_existing_user(proxy_addr, user):
        ((username, email, _), _) = user
        password = str(uuid.uuid4())
        r = make_requests(
            'POST',
            proxy_addr,
            '/signup',
            data={
                'username': username,
                'email': email,
                'password': password})
        assert r.status_code == 403
        assert len(r.cookies) == 0

    @staticmethod
    def test_login(proxy_addr, jwt_public, user):
        ((username, _, password), _) = user
        r = make_requests(
            'POST',
            proxy_addr,
            '/login',
            data={
                'username': username,
                'password': password})
        assert r.status_code == 200
        TestAuth.check_jwt(r.cookies, jwt_public, username)

    @staticmethod
    def test_login_with_wrong_password(proxy_addr, user):
        ((username, _, _), _) = user
        password = str(uuid.uuid4())
        r = make_requests(
            'POST',
            proxy_addr,
            '/login',
            data={
                'username': username,
                'password': password})
        assert r.status_code == 403
        assert len(r.cookies) == 0

    @staticmethod
    def test_login_with_non_existing_user(proxy_addr):
        username = str(uuid.uuid4())
        password = str(uuid.uuid4())
        r = make_requests(
            'POST',
            proxy_addr,
            '/login',
            data={
                'username': username,
                'password': password})
        assert r.status_code == 403
        assert len(r.cookies) == 0

    @staticmethod
    def test_whoami(proxy_addr, user):
        ((username, _, _), cookies) = user
        r = make_requests('GET', proxy_addr, '/whoami', cookies=cookies)
        assert r.status_code == 200
        assert r.content == f'Hello, {username}'.encode()

    @staticmethod
    def test_whoami_without_cookie(proxy_addr):
        r = make_requests('GET', proxy_addr, '/whoami')
        assert r.status_code == 401

    @staticmethod
    def test_whoami_with_wrong_cookie(proxy_addr):
        r = make_requests(
            'GET',
            proxy_addr,
            '/whoami',
            cookies={
                'jwt': 'not jwt'})
        assert r.status_code == 400

    @staticmethod
    def test_whoami_with_cookie_of_non_existing_user(proxy_addr, jwt_private):
        token = generate_jwt(jwt_private, 'Bob')
        r = make_requests('GET', proxy_addr, '/whoami', cookies={'jwt': token})
        assert r.status_code == 400

    @staticmethod
    def test_whoami_with_cookie_signed_by_other_secret(proxy_addr):
        token = generate_hs256_jwt('wrong secret', 'Alice')
        r = make_requests('GET', proxy_addr, '/whoami', cookies={'jwt': token})
        assert r.status_code == 400
    
    # @staticmethod
    # def test_update_profile(proxy_addr):
    #     ((username, _), cookies) = user
    #     profile_data = {'name': 'Артемий', 
    #                     'surname': 'Новиков', 
    #                     'phone-number': '+79651234567',
    #                     'burthday': '11-09-2004',
    #                     'email': f'{username}_new@mail.com'
    #                     }
    #     r = make_requests('POST', proxy_addr, '/update-profile', data=profile_data, cookies={'jwt': cookies})
    #     assert r.status_code == 200
        