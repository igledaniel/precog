# coding: utf-8
from logging import DEBUG, INFO, getLogger, FileHandler, StreamHandler, Formatter
from os.path import join, isdir, isfile
from traceback import format_exc
from urllib import urlencode
from functools import wraps
from operator import attrgetter
from urlparse import urlparse, urljoin
from mimetypes import guess_type
from os import environ
from uuid import uuid4
from time import time
import hmac, json, hashlib
import sys

from flask import Flask, Response, redirect, request, make_response, render_template, session, current_app
from flask_sslify import SSLify
import requests

from requests import post
from requests_oauthlib import OAuth2Session
from git import (
    Getter, is_authenticated, repo_exists, split_branch_path, get_circle_artifacts,
    select_path, _LONGTIME, get_branch_info, ERR_TESTS_PENDING, ERR_TESTS_FAILED,
    skip_webhook_payload, get_webhook_commit_info, post_github_status
    )
from href import needs_redirect, get_redirect, absolute_url
from util import errors_logged, nice_relative_time, parse_webhook_config, err_codes

from git import github_client_id, github_client_secret, FAKE_TOKEN, GithubDisallowed
from git import ERR_NO_REPOSITORY, ERR_TESTS_PENDING, ERR_TESTS_FAILED, ERR_NO_REF_STATUS
flask_secret_key = environ.get('FLASK_SECRET') or 'poop'

webhook_config = parse_webhook_config(*[val for (key, val) in environ.items()
                                        if key.startswith('WEBHOOK_CONFIG_')
                                        or key == 'WEBHOOK_CONFIG'])

app = Flask(__name__)
if sys.argv[0] != 'test.py':
    getLogger('precog').info('SSLifying')
    SSLify(app)
app.secret_key = flask_secret_key
app.jinja_env.filters['nice_relative_time'] = nice_relative_time
app.config['HOOK_SECRETS_TOKENS'] = webhook_config

@app.before_first_request
def adjust_log_level():
    getLogger('precog').setLevel(DEBUG if app.debug else INFO)

def make_redirect(slash_count):
    ''' Return a flask.redirect for the current flask.request.
    '''
    referer_url = request.headers.get('Referer')

    request_part = request.path + '?{}'.format(request.query_string).rstrip('?')
    location = get_redirect(request_part, referer_url, slash_count)
    other = redirect(absolute_url(request, location), 302)
    other.headers['Cache-Control'] = 'no-store private'
    other.headers['Vary'] = 'Referer'

    return other

def handle_redirects(untouched_route):
    '''
    '''
    def maybe_add_slashes(request_path, GET, *args, **kwargs):
        ''' Redirect with trailing slashes if necessary.
        '''
        # Look for a missing trailing slash at the repository root.
        split_req = request_path.lstrip('/').split('/', 2)
        
        if len(split_req) == 2 and split_req[-1] != '':
            # There are two full components in the path: owner and repo,
            req_owner, req_repo = split_req
            
            if repo_exists(req_owner, req_repo, GET):
                # Missing a trailing slash for the branch listing.
                return redirect(absolute_url(request, '{}/'.format(request_path)), 302)
        
        if len(split_req) == 3 and split_req[-1] != '':
            # There are three full components in the path: owner, repo, and ref.
            req_owner, req_repo, req_ref_path = split_req
            req_ref, req_path = split_branch_path(req_owner, req_repo, req_ref_path, GET)
            
            if req_path == '' and not req_ref_path.endswith('/'):
                # Missing a trailing slash at the root of the repository.
                return redirect(absolute_url(request, '{}/'.format(request_path)), 302)
        
        return untouched_route(*args, **kwargs)
    
    @wraps(untouched_route)
    def wrapper(*args, **kwargs):
        ''' Redirect under repository root based on referer if necessary.
        '''
        GET = Getter((get_token().get('access_token'), 'x-oauth-basic')).get
        
        # See if the OK hand sign (U+1F44C) was given.
        if request.args.get('go') == u'\U0001f44c':
            return untouched_route(*args, **kwargs)

        # See if there's a referer at all.
        referer_url = request.headers.get('Referer')
        
        if not referer_url:
            # No referer, no redirect.
            return maybe_add_slashes(request.path, GET, *args, **kwargs)
        
        # See if the referer path is long enough to suggest a redirect.
        referer_path = urlparse(referer_url).path
        split_path = referer_path.lstrip('/').split('/', 2)
        
        if len(split_path) != 3:
            # Not long enough.
            return maybe_add_slashes(request.path, GET, *args, **kwargs)
        
        # Talk to Github about the path and find a ref name.
        path_owner, path_repo, path_ref = split_path

        if not repo_exists(path_owner, path_repo, GET):
            # No repo by this name, no redirect.
            return maybe_add_slashes(request.path, GET, *args, **kwargs)
        
        ref, _ = split_branch_path(path_owner, path_repo, path_ref, GET)
        
        if ref is None:
            # No ref identified, no redirect.
            return maybe_add_slashes(request.path, GET, *args, **kwargs)
        
        # Usually 3, but maybe more?
        slash_count = 2 + len(ref.split('/'))
        
        # See if a redirect is necessary.
        if needs_redirect(request.host, request.path, referer_url, slash_count):
            return make_redirect(slash_count)
        
        # Otherwise, proceed as normal.
        return maybe_add_slashes(request.path, GET, *args, **kwargs)
    
    return wrapper

def handle_authentication(untouched_route):
    '''
    '''
    @wraps(untouched_route)
    def wrapper(account, repo, *args, **kwargs):
        ''' Prompt user to authenticate with Github if necessary.
        '''
        try:
            response = untouched_route(account, repo, *args, **kwargs)
        except GithubDisallowed:
            return make_401_response()
        else:
            return response

        access_token = get_token().get('access_token')
        GET = Getter((access_token, 'x-oauth-basic')).get
    
        if access_token is None or not is_authenticated(GET):
            return make_401_response()
        
        return untouched_route(account, repo, *args, **kwargs)
    
    return wrapper

def enforce_signature(route_function):
    ''' Look for a signature and bark if it's wrong.
    '''
    @wraps(route_function)
    def decorated_function(*args, **kwargs):
        try:
            webhook_payload = json.loads(request.data.decode('utf8'))
            owner, repo, _, _ = get_webhook_commit_info(current_app, webhook_payload)
        except:
            return Response(json.dumps({'error': 'Unknown repository'}),
                            401, content_type='application/json')
            
        owner_repo = '{}/{}'.format(owner, repo)
        secret_key = current_app.config['HOOK_SECRETS_TOKENS'].get(owner_repo, {}).get('secret')
    
        #if not secret_key:
        #    # No configured secrets means no signature needed.
        #    getLogger('precog').info('No /hook signature required')
        #    return route_function(*args, **kwargs)
        
        if secret_key is None:
            return Response(json.dumps({'error': 'Missing key'}),
                            401, content_type='application/json')
    
        if 'X-Hub-Signature' not in request.headers:
            # Missing required signature is an error.
            getLogger('precog').warning('No /hook signature provided')
            return Response(json.dumps({'error': 'Missing signature'}),
                            401, content_type='application/json')

        def _sign(key):
            hash = hmac.new(key, request.data, hashlib.sha1)
            return 'sha1={}'.format(hash.hexdigest())

        actual = request.headers.get('X-Hub-Signature')
        expected = _sign(secret_key)
        
        if actual != expected:
            # Signature mismatch is an error.
            getLogger('precog').warning('Mismatched /hook signatures: {actual} vs. {expected}'.format(**locals()))
            return Response(json.dumps({'error': 'Invalid signature'}),
                            401, content_type='application/json')

        getLogger('precog').debug('Matching /hook signature: {actual}'.format(**locals()))
        return route_function(*args, **kwargs)

    return decorated_function

def get_token():
    ''' Get OAuth token from flask.session, or a fake one guaranteed to fail.
    '''
    token = dict(token_type='bearer', access_token=FAKE_TOKEN)
    token.update(session.get('token', {}))
    
    return token

def make_401_response():
    ''' Create an HTTP 401 Not Authorized response to trigger Github OAuth.
    
        Start by redirecting the user to Github OAuth authorization page:
        http://developer.github.com/v3/oauth/#redirect-users-to-request-github-access
    '''
    state_id = str(uuid4())
    states = session.get('states', {})
    states[state_id] = dict(redirect=request.url, created=time())
    session['states'] = states
    
    data = dict(scope='user,repo', client_id=github_client_id, state=state_id)
    href = 'https://github.com/login/oauth/authorize?' + urlencode(data)
    
    auth = make_response(render_template('error-authenticate.html', href=href, codes=err_codes), 401)
    auth.headers['X-Redirect'] = href
    
    return auth

def make_404_response(template, vars):
    '''
    '''
    return make_response(render_template(template, **vars), 404)

def make_500_response(error, traceback):
    '''
    '''
    try:
        message = unicode(error)
    except UnicodeDecodeError:
        message = str(error).decode('latin-1')
    
    vars = dict(error=message, traceback=traceback, codes=err_codes)
    
    return make_response(render_template('error-runtime.html', **vars), 500)

@app.route('/')
@errors_logged
@handle_redirects
def hello_world():
    id = session.get('id', None)
    return render_template('index.html', id=id, request=request)

@app.route('/.well-known/status')
@errors_logged
@handle_redirects
def wellknown_status():
    status = '''
    {
      "status": "ok",
      "updated": %d,
      "dependencies": [ ],
      "resources": { }
    }
    ''' % time()
    
    resp = make_response(status, 200)
    resp.headers['Content-Type'] = 'application/json'

    return resp

@app.route('/hook', methods=['POST'])
@errors_logged
@enforce_signature
@handle_redirects
def webhook():

    payload = json.loads(request.data.decode('utf8'))

    if skip_webhook_payload(payload):
        return 'Nevermind'

    owner, repo, commit_sha, status_url = get_webhook_commit_info(current_app, payload)
    target_path = u'/{owner}/{repo}/{commit_sha}/'.format(**locals())
    
    status = dict(context='mapzen/precog', state='success',
                  target_url=urljoin(request.url, target_path),
                  description=u'Preview your changes')

    owner_repo = '{}/{}'.format(owner, repo)
    token = current_app.config['HOOK_SECRETS_TOKENS'].get(owner_repo, {}).get('token')
    
    try:
        post_github_status(status_url, status, (token, 'x-oauth-basic'))
    except ValueError as err:
        if err.message.startswith('Failed status post to https://api.github.com'):
            return make_response(err.message, 403)
        raise
    
    return 'Yo.'

@app.route('/oauth/callback')
@errors_logged
def get_oauth_callback():
    ''' Handle Github's OAuth callback after a user authorizes.
    
        http://developer.github.com/v3/oauth/#github-redirects-back-to-your-site
    '''
    if 'error' in request.args:
        return render_template('error-oauth.html', reason="you didn't authorize access to your account.")
    
    try:
        code, state_id = request.args['code'], request.args['state']
    except:
        return render_template('error-oauth.html', reason='missing code or state in callback.')
    
    try:
        state = session['states'].pop(state_id)
    except:
        return render_template('error-oauth.html', reason='state "%s" not found?' % state_id)
    
    #
    # Exchange the temporary code for an access token:
    # http://developer.github.com/v3/oauth/#parameters-1
    #
    data = dict(client_id=github_client_id, code=code, client_secret=github_client_secret)
    resp = post('https://github.com/login/oauth/access_token', urlencode(data),
                headers={'Accept': 'application/json'})
    auth = resp.json()
    
    if 'error' in auth:
        return render_template('error-oauth.html', reason='Github said "%(error)s".' % auth)
    
    elif 'access_token' not in auth:
        return render_template('error-oauth.html', reason="missing `access_token`.")
    
    session['token'] = auth
    
    #
    # Figure out who's here.
    #
    url = 'https://api.github.com/user'
    id = OAuth2Session(github_client_id, token=session['token']).get(url).json()
    id = dict(login=id['login'], avatar_url=id['avatar_url'], html_url=id['html_url'])
    session['id'] = id
    
    other = redirect(absolute_url(request, state['redirect']), 302)
    other.headers['Cache-Control'] = 'no-store private'
    other.headers['Vary'] = 'Referer'

    return other

@app.route('/logout', methods=['POST'])
@errors_logged
def logout():
    '''
    '''
    if 'id' in session:
        session.pop('id')

    if 'token' in session:
        session.pop('token')
    
    return redirect(absolute_url(request, '/'), 302)

@app.route('/<account>/<repo>')
@errors_logged
@handle_authentication
@handle_redirects
def repo_only(account, repo):
    ''' Add a slash.
    '''
    access_token = get_token().get('access_token')
    GET = Getter((access_token, 'x-oauth-basic'), throws4XX=True).get
    return str(repo_exists(account, repo, GET))

@app.route('/<account>/<repo>/')
@errors_logged
@handle_authentication
@handle_redirects
def repo_only_slash(account, repo):
    ''' Show a list of branch names.
    '''
    access_token = get_token().get('access_token')
    GET = Getter((access_token, 'x-oauth-basic'), throws4XX=True).get
    template_args = dict(account=account, repo=repo)
    branches = sorted(get_branch_info(account, repo, GET), key=attrgetter('age'), reverse=False)
    
    if request.args.get('sort') == 'name':
        branches.sort(key=attrgetter('name'))
    
    return render_template('branches.html', branches=branches, **template_args)

@app.route('/<account>/<repo>/<ref>')
@errors_logged
@handle_authentication
@handle_redirects
def repo_ref(account, repo, ref):
    ''' Redirect to add trailing slash.
    '''
    access_token = get_token().get('access_token')
    GET = Getter((access_token, 'x-oauth-basic'), throws4XX=True).get
    return str(repo_exists(account, repo, GET))

@app.route('/<account>/<repo>/<path:ref_path>')
@errors_logged
@handle_authentication
@handle_redirects
def repo_ref_path(account, repo, ref_path):
    access_token = get_token().get('access_token')
    GET = Getter((access_token, 'x-oauth-basic'), throws4XX=True).get
    template_args = dict(account=account, repo=repo)
    
    if not repo_exists(account, repo, GET):
        return make_404_response('no-such-repo.html', template_args)
    
    ref, path = split_branch_path(account, repo, ref_path, GET)
    
    if ref is None:
        return make_404_response('no-such-ref.html', dict(ref=ref_path, **template_args))
    
    try:
        artifacts = get_circle_artifacts(account, repo, ref, GET)
        artifact_url = artifacts.get(select_path(artifacts, path))
    except RuntimeError as err:
        vars = dict(error=err, codes=err_codes, git_ref=ref)
        if err.args[0] == ERR_TESTS_PENDING:
            return make_response(render_template('error-pending.html', refresh=request.path, **vars), 200)
        elif err.args[0] == ERR_TESTS_FAILED:
            return make_response(render_template('error-failed.html', **vars), 200)
        else:
            return make_response(render_template('error-runtime.html', **vars), 400)
    
    if artifact_url is None:
        return make_404_response('error-404.html', dict(ref=ref, path=path, **template_args))

    try:
        if urlparse(artifact_url).scheme == 'file':
            mimetype, _ = guess_type(artifact_url)
            with open(urlparse(artifact_url).path) as file:
                content = file.read()
        else:
            artifact_resp = GET(artifact_url, _LONGTIME)
            if artifact_resp.status_code != 200:
                raise IOError('Bad response from CircleCI: HTTP {}'.format(artifact_resp.status_code))
            content = artifact_resp.content
            mimetype = artifact_resp.headers.get('Content-Type', '')
    except IOError as err:
        return make_response(render_template('error-runtime.html', error=err, codes=err_codes), 500)
    
    return Response(content, headers={'Content-Type': mimetype, 'Cache-Control': 'no-store private'})

@app.route('/<path:path>')
@errors_logged
@handle_redirects
def all_other_paths(path):
    '''
    '''
    return u'¯\_(ツ)_/¯'

if environ.get('app-logfile', None):
    handler = FileHandler(environ['app-logfile'])
    handler.setFormatter(Formatter('%(process)05s %(asctime)s %(levelname)06s: %(message)s'))

else:
    handler = StreamHandler()
    handler.setFormatter(Formatter('%(process)05s %(levelname)06s: %(message)s'))

getLogger('precog').addHandler(handler)

if __name__ == '__main__':
    app.run('localhost', debug=True)
