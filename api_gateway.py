from flask import Flask, request
import requests
import datetime
from werkzeug.security import generate_password_hash, check_password_hash
from flask.json import jsonify
from http import HTTPStatus
from functools import wraps
import jwt
from requests.models import Response

app = Flask(__name__)
app.config['SECRET_KEY'] = '2b01ddd83c7b5778cb05d8f66d94c727'


class Service:
    total_services = 0

    def __init__(self, name, address, port):
        self.name = name
        self.address = address
        self.port = port
        self.id = Service.total_services
        Service.total_services += 1

    @property
    def url(self):
        return f"http://{self.address}:{self.port}"


class ServiceStatus:
    def __init__(self):
        self.last_time = 0
        self.state = 'closed'
        self.failed_attempts = 0


class CircuitBreaker:

    def __init__(self, timeout, fail_count):
        self.services = {}
        self.timeout = timeout
        self.fail_count = fail_count

    def send_request(self, service, func, url, *args, **kwargs):
        if service.id in self.services:
            stats = self.services[service.id]
            if stats.state == 'open':
                if datetime.datetime.now() - stats.last_time > datetime.timedelta(milliseconds=self.timeout):
                    stats.state = 'half-open'
            if stats.state == 'open':
                response = Response()
                response.status_code = HTTPStatus.SERVICE_UNAVAILABLE
                response._content = b"{'message': 'Service in cooldown'}"
                response.headers['Content-Type'] = 'application/json'
                return response
        else:
            stats = self.services[service.id] = ServiceStatus()
        response = Response()
        try:
            stats.last_time = datetime.datetime.now()
            response = func(service.url + url, timeout=0.5, *args, **kwargs)
            if response.status_code in [500, 501, 502, 503, 504, 505, 506, 507, 508, 509, 510, 598, 599]:
                if stats.state == 'closed':
                    stats.failed_attempts += 1
                else:
                    stats.state = 'open'
            elif stats.state == 'half-open':
                stats.failed_attempts = 0
                stats.state = 'closed'

        except Exception:
            stats.failed_attempts += 1
            response = Response()
            response.status_code = HTTPStatus.SERVICE_UNAVAILABLE
            response._content = b"{'message' : 'Service unavailable'}"
            response.headers['Content-Type'] = 'application/json'

        if stats.failed_attempts >= self.fail_count:
            stats.state = 'open'
            stats.last_time = datetime.datetime.now()

        return response


account_service = Service("Account Service", "account-service", 5000)
book_service = Service("Book Service", "book-service", 1000)
circuit_breaker = CircuitBreaker(10000, 3)


def as_response(response):
    return response.content, response.status_code, response.headers.items()


def token_required(func):
    @wraps(func)
    def run_with_username(*args, **kwargs):
        token = request.headers.get('x-access-token')
        if not token:
            return jsonify(message="No token is given"), HTTPStatus.UNAUTHORIZED
        try:
            payload = jwt.decode(token, app.config.get('SECRET_KEY'), algorithms='HS256')
            username = payload['sub']
            exp = datetime.datetime.fromtimestamp(payload['exp'])
            if datetime.datetime.now() >= exp:
                return jsonify(message="Token has expired."), HTTPStatus.UNAUTHORIZED

        except Exception as e:
            return jsonify(message=str(e)), HTTPStatus.UNAUTHORIZED
        return func(username, *args, **kwargs)

    return run_with_username


@app.route('/signup', methods=['POST'])
def signup():
    json = request.json
    password = json.pop('password', None)

    if not password:
        return jsonify(message='Password is not given'), HTTPStatus.BAD_REQUEST

    json['hashed_passwd'] = generate_password_hash(password)
    response = circuit_breaker.send_request(account_service, requests.post, "/create_user", json=json)
    return as_response(response)


@app.route('/login', methods=['POST'])
def login():
    json = request.json
    username = json.get('username')
    password = json.get('password')
    if not username:
        return jsonify(message="Username is not given"), HTTPStatus.BAD_REQUEST
    if not password:
        return jsonify(message="Password is not given"), HTTPStatus.BAD_REQUEST
    get_user_url = f"/get_user/{username}"
    response = circuit_breaker.send_request(account_service, requests.get, get_user_url)
    if response.status_code != HTTPStatus.OK:
        return as_response(response)

    found_user = response.json()['user']
    expire_time = (datetime.datetime.now() + datetime.timedelta(days=1)).timestamp()
    if check_password_hash(found_user['hashed_passwd'], password):
        payload = {
            'sub': username,
            'exp': expire_time
        }
        token = jwt.encode(payload, app.config.get('SECRET_KEY'), algorithm='HS256')
        return jsonify(message="Login Successful", jwt=token), HTTPStatus.OK
    return jsonify(message='Invalid Password'), HTTPStatus.UNAUTHORIZED


@app.route('/show_profile', methods=['GET'])
@token_required
def show_profile(username):
    get_user_url = f"/get_user/{username}"
    response = circuit_breaker.send_request(account_service, requests.get, get_user_url)

    if response.status_code != HTTPStatus.OK:
        return as_response(response)

    found_user = response.json()['user']
    found_user.pop('hashed_passwd')

    return jsonify(user=found_user), HTTPStatus.OK


@app.route('/update_profile', methods=['POST'])
@token_required
def update_profile(username):
    modify_user_url = f"/modify_user/{username}"
    json = request.json
    response = circuit_breaker.send_request(account_service, requests.put, modify_user_url, json=json)
    return as_response(response)


@app.route('/show_clients', methods=['GET'])
@token_required
def show_clients(username):
    get_user_url = f"/get_user/{username}"
    response = circuit_breaker.send_request(account_service, requests.get, get_user_url)
    if response.status_code != HTTPStatus.OK:
        return as_response(response)

    found_user = response.json()['user']
    if not found_user['isAdmin']:
        return jsonify(message="Only admins can view clients list."), HTTPStatus.FORBIDDEN

    get_clients_url = "/show_clients"
    response = circuit_breaker.send_request(account_service, requests.get, get_clients_url)
    return as_response(response)


@app.route('/books', methods=['GET'])
@token_required
def show_books(username):
    get_books_url = "/books/q"
    response = circuit_breaker.send_request(book_service, requests.get, get_books_url, params=request.args)
    return as_response(response)


@app.route('/books/create', methods=['POST'])
@token_required
def create_book(username):
    get_user_url = f"/get_user/{username}"
    response = circuit_breaker.send_request(account_service, requests.get, get_user_url)
    if response.status_code != HTTPStatus.OK:
        return as_response(response)

    found_user = response.json()['user']
    if not found_user['isAdmin']:
        return jsonify(message="Only admins can create books."), HTTPStatus.FORBIDDEN

    create_book_url = "/books/create"
    json = request.json
    json['admin'] = username
    response = circuit_breaker.send_request(book_service, requests.post, create_book_url, json=json)
    return as_response(response)



if __name__ == '__main__':
    app.run(port=80, debug=True)