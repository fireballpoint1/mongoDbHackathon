"""Python Flask WebApp Auth0 integration example
"""
from functools import wraps
import json
from os import environ as env
from werkzeug.exceptions import HTTPException

from dotenv import load_dotenv, find_dotenv
from flask import Flask
from flask import jsonify
from flask import redirect
from flask import render_template
from flask import session
from flask import url_for
from authlib.integrations.flask_client import OAuth
from six.moves.urllib.parse import urlencode
from pymongo import MongoClient
from flask_pymongo import PyMongo
import requests
from requests.structures import CaseInsensitiveDict
import base64

import constants

ENV_FILE = find_dotenv()
if ENV_FILE:
    load_dotenv(ENV_FILE)


LOUVRE_APP = constants.LOUVRE_APP
MONGO_PRIMARY_CONN = constants.MONGO_PRIMARY_CONN

app = Flask(__name__, static_url_path='/public', static_folder='./public')
app.secret_key = constants.SECRET_KEY
app.debug = True

## setup mongo client
uri = MONGO_PRIMARY_CONN
client = MongoClient(uri)
db = client.louvre
configuration = db['configuration']
louvre_app = configuration.find_one({'louvre_app':LOUVRE_APP})
print(louvre_app)
####### ENVIRONMENT VARIABLES ######
AUTH0_CALLBACK_URL = louvre_app['auth0_callback_url']
AUTH0_CLIENT_ID = louvre_app['auth0_client_id']
AUTH0_CLIENT_SECRET = louvre_app['auth0_client_secret']
AUTH0_DOMAIN = louvre_app['auth0_domain']
AUTH0_BASE_URL = 'https://' + AUTH0_DOMAIN
AUTH0_AUDIENCE = louvre_app['audience']
PAANS_INTEGRATION = louvre_app['paans_integration']
APP_URL = louvre_app["louvre_app_url"]
PAANS_POLICY_TYPE = louvre_app['paans_policy_type']
PAANS_POLICY_REGION = louvre_app['paans_policy_region']
PAANS_POLICY_LANG = louvre_app['paans_policy_lang']
PAANS_API_URL = louvre_app['paans_api_url']
print(AUTH0_AUDIENCE, AUTH0_CLIENT_ID)

@app.errorhandler(Exception)
def handle_auth_error(ex):
    response = jsonify(message=str(ex))
    response.status_code = (ex.code if isinstance(ex, HTTPException) else 500)
    return response


oauth = OAuth(app)

auth0 = oauth.register(
    'auth0',
    client_id=AUTH0_CLIENT_ID,
    client_secret=AUTH0_CLIENT_SECRET,
    api_base_url=AUTH0_BASE_URL,
    access_token_url=AUTH0_BASE_URL + '/oauth/token',
    authorize_url=AUTH0_BASE_URL + '/authorize',
    client_kwargs={
        'scope': 'openid profile email',
    },
)


def requires_auth(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if constants.PROFILE_KEY not in session:
            return redirect('/login')
        return f(*args, **kwargs)

    return decorated


# Controllers API
@app.route('/')
def home():
    return render_template('home.html')


@app.route('/callback')
def callback_handling():
    auth0.authorize_access_token()
    resp = auth0.get('userinfo')
    userinfo = resp.json()


    session[constants.JWT_PAYLOAD] = userinfo
    print("userinfo", userinfo)
    session[constants.USER_EMAIL] = userinfo['email']
    session[constants.PROFILE_KEY] = {
        'user_id': userinfo['sub'],
        'name': userinfo['name'],
        'picture': userinfo['picture']
    }
    return redirect('/logged-in')


@app.route('/login')
def login():
    
    return auth0.authorize_redirect(redirect_uri=AUTH0_CALLBACK_URL, audience=AUTH0_AUDIENCE)


@app.route('/logout')
def logout():
    session.clear()
    params = {'returnTo': url_for('home', _external=True), 'client_id': AUTH0_CLIENT_ID}
    return redirect(auth0.api_base_url + '/v2/logout?' + urlencode(params))


@app.route('/logged-in')
@requires_auth
def loggedIn():
    print("email",session[constants.USER_EMAIL])
    return redirect('/dashboard')

@app.route('/dashboard')
@requires_auth
def dashboard():
    return render_template('dashboard.html',
                           userinfo=session[constants.PROFILE_KEY],
                           userinfo_pretty=json.dumps(session[constants.JWT_PAYLOAD], indent=4))


if __name__ == "__main__":
    app.run(host='0.0.0.0', port=env.get('PORT', 3000))
