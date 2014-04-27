# coding: utf-8

from base64 import b64encode
import functools
import hashlib
import json
import re

from flask.ext import login
from flask.ext.oauthlib import client as oauth
from google.appengine.api import urlfetch
from google.appengine.api import users
from google.appengine.ext import ndb
from werkzeug import urls
import flask
import unidecode

import config
import model
import task
import util

from main import app

_signals = flask.signals.Namespace()

###############################################################################
# Flask Login
###############################################################################
login_manager = login.LoginManager()


class AnonymousUser(login.AnonymousUserMixin):
  id = 0
  admin = False
  name = 'Anonymous'
  user_db = None

  def key(self):
    return None

  def has_permission(self, permission):
    return False

login_manager.anonymous_user = AnonymousUser


class FlaskUser(AnonymousUser):
  def __init__(self, user_db):
    self.user_db = user_db
    self.id = user_db.key.id()
    self.name = user_db.name
    self.admin = user_db.admin

  def key(self):
    return self.user_db.key.urlsafe()

  def get_id(self):
    return self.user_db.key.urlsafe()

  def is_authenticated(self):
    return True

  def is_active(self):
    return self.user_db.active

  def is_anonymous(self):
    return False

  def has_permission(self, permission):
    return self.user_db.has_permission(permission)


@login_manager.user_loader
def load_user(key):
  user_db = ndb.Key(urlsafe=key).get()
  if user_db:
    return FlaskUser(user_db)
  return None


login_manager.init_app(app)


def current_user_id():
  return login.current_user.id


def current_user_key():
  return login.current_user.user_db.key if login.current_user.user_db else None


def current_user_db():
  return login.current_user.user_db


def is_logged_in():
  return login.current_user.id != 0


###############################################################################
# Decorators
###############################################################################
def login_required(f):
  decorator_order_guard(f, 'auth.login_required')

  @functools.wraps(f)
  def decorated_function(*args, **kws):
    if is_logged_in():
      return f(*args, **kws)
    if flask.request.path.startswith('/_s/'):
      return flask.abort(401)
    return flask.redirect(flask.url_for('signin', next=flask.request.url))
  return decorated_function


def admin_required(f):
  decorator_order_guard(f, 'auth.admin_required')

  @functools.wraps(f)
  def decorated_function(*args, **kws):
    if is_logged_in() and current_user_db().admin:
      return f(*args, **kws)
    if not is_logged_in() and flask.request.path.startswith('/_s/'):
      return flask.abort(401)
    if not is_logged_in():
      return flask.redirect(flask.url_for('signin', next=flask.request.url))
    return flask.abort(403)
  return decorated_function


permission_registered = _signals.signal('permission-registered')


def permission_required(permission=None, methods=None):
  def permission_decorator(f):
    decorator_order_guard(f, 'auth.permission_required')

    # default to decorated function name as permission
    perm = permission or f.func_name
    meths = [m.upper() for m in methods] if methods else None

    permission_registered.send(f, permission=perm)

    @functools.wraps(f)
    def decorated_function(*args, **kws):
      if meths and flask.request.method.upper() not in meths:
        return f(*args, **kws)
      if is_logged_in() and current_user_db().has_permission(perm):
        return f(*args, **kws)
      if not is_logged_in():
        if flask.request.path.startswith('/_s/'):
          return flask.abort(401)
        return flask.redirect(flask.url_for('signin', next=flask.request.url))
      return flask.abort(403)
    return decorated_function
  return permission_decorator


###############################################################################
# Sign in stuff
###############################################################################
@app.route('/login/')
@app.route('/signin/')
def signin():
  next_url = util.get_next_url()

  bitbucket_signin_url = url_for_signin('bitbucket', next_url)
  dropbox_signin_url = url_for_signin('dropbox', next_url)
  facebook_signin_url = url_for_signin('facebook', next_url)
  github_signin_url = url_for_signin('github', next_url)
  google_signin_url = url_for_signin('google', next_url)
  instgram_signin_url = url_for_signin('instagram', next_url)
  linkedin_signin_url = url_for_signin('linkedin', next_url)
  odnoklassniki_signin_url = flask.url_for('signin_odnoklassniki', next=next_url)
  reddit_signin_url = url_for_signin('reddit', next_url)
  stackoverflow_signin_url = url_for_signin('stackoverflow', next_url)
  twitter_signin_url = url_for_signin('twitter', next_url)
  vk_signin_url = url_for_signin('vk', next_url)
  microsoft_signin_url = url_for_signin('microsoft', next_url)
  yahoo_signin_url = url_for_signin('yahoo', next_url)

  return flask.render_template(
      'signin.html',
      title='Please sign in',
      html_class='signin',
      bitbucket_signin_url=bitbucket_signin_url,
      dropbox_signin_url=dropbox_signin_url,
      facebook_signin_url=facebook_signin_url,
      github_signin_url=github_signin_url,
      google_signin_url=google_signin_url,
      instagram_signin_url=instgram_signin_url,
      linkedin_signin_url=linkedin_signin_url,
      odnoklassniki_signin_url=odnoklassniki_signin_url,
      reddit_signin_url=reddit_signin_url,
      stackoverflow_signin_url=stackoverflow_signin_url,
      twitter_signin_url=twitter_signin_url,
      vk_signin_url=vk_signin_url,
      microsoft_signin_url=microsoft_signin_url,
      yahoo_signin_url=yahoo_signin_url,
      next_url=next_url,
    )


@app.route('/signout/')
def signout():
  login.logout_user()
  flask.flash(u'You have been signed out.', category='success')
  return flask.redirect(util.param('next') or flask.url_for('signin'))


###############################################################################
# Google
###############################################################################
@app.route('/signin/google/')
def signin_google():
  save_request_params()
  google_url = users.create_login_url(flask.url_for('google_authorized'))
  return flask.redirect(google_url)


@app.route('/_s/callback/google/authorized/')
def google_authorized():
  google_user = users.get_current_user()
  if google_user is None:
    flask.flash(u'You denied the request to sign in.')
    return flask.redirect(util.get_next_url())

  user_db = retrieve_user_from_google(google_user)
  return signin_user_db(user_db)


def retrieve_user_from_google(google_user):
  auth_id = 'federated_%s' % google_user.user_id()
  user_db = model.User.get_by('auth_ids', auth_id)
  if user_db:
    if not user_db.admin and users.is_current_user_admin():
      user_db.admin = True
      user_db.put()
    return user_db

  return create_user_db(
      auth_id,
      util.create_name_from_email(google_user.email()),
      google_user.email(),
      google_user.email(),
      verified=True,
      admin=users.is_current_user_admin(),
    )


###############################################################################
# Twitter
###############################################################################
twitter_oauth = oauth.OAuth()

app.config['TWITTER'] = dict(
    base_url='https://api.twitter.com/1.1/',
    request_token_url='https://api.twitter.com/oauth/request_token',
    access_token_url='https://api.twitter.com/oauth/access_token',
    authorize_url='https://api.twitter.com/oauth/authorize',
    consumer_key=config.CONFIG_DB.twitter_consumer_key,
    consumer_secret=config.CONFIG_DB.twitter_consumer_secret,
  )

twitter = twitter_oauth.remote_app('twitter', app_key='TWITTER')
twitter_oauth.init_app(app)


@app.route('/_s/callback/twitter/oauth-authorized/')
def twitter_authorized():
  response = twitter.authorized_response()
  if response is None:
    flask.flash(u'You denied the request to sign in.')
    return flask.redirect(util.get_next_url())

  flask.session['oauth_token'] = (
      response['oauth_token'],
      response['oauth_token_secret'],
    )
  user_db = retrieve_user_from_twitter(response)
  return signin_user_db(user_db)


@twitter.tokengetter
def get_twitter_token():
  return flask.session.get('oauth_token')


@app.route('/signin/twitter/')
def signin_twitter():
  try:
    return signin_oauth(twitter)
  except:
    flask.flash(
        u'Something went wrong with Twitter sign in. Please try again.',
        category='danger',
      )
    return flask.redirect(flask.url_for('signin', next=util.get_next_url()))


def retrieve_user_from_twitter(response):
  auth_id = 'twitter_%s' % response['user_id']
  user_db = model.User.get_by('auth_ids', auth_id)
  if user_db:
    return user_db

  return create_user_db(
      auth_id,
      response['screen_name'],
      response['screen_name'],
    )


###############################################################################
# Facebook
###############################################################################
facebook_oauth = oauth.OAuth()

app.config['FACEBOOK'] = dict(
    base_url='https://graph.facebook.com/',
    request_token_url=None,
    access_token_url='/oauth/access_token',
    authorize_url='https://www.facebook.com/dialog/oauth',
    consumer_key=config.CONFIG_DB.facebook_app_id,
    consumer_secret=config.CONFIG_DB.facebook_app_secret,
    request_token_params={'scope': 'email'},
  )

facebook = facebook_oauth.remote_app('facebook', app_key='FACEBOOK')
facebook_oauth.init_app(app)


@app.route('/_s/callback/facebook/oauth-authorized/')
def facebook_authorized():
  response = facebook.authorized_response()
  if response is None:
    flask.flash(u'You denied the request to sign in.')
    return flask.redirect(util.get_next_url())

  flask.session['oauth_token'] = (response['access_token'], '')
  me = facebook.get('/me')
  user_db = retrieve_user_from_facebook(me.data)
  return signin_user_db(user_db)


@facebook.tokengetter
def get_facebook_oauth_token():
  return flask.session.get('oauth_token')


@app.route('/signin/facebook/')
def signin_facebook():
  return signin_oauth(facebook)


def retrieve_user_from_facebook(response):
  auth_id = 'facebook_%s' % response['id']
  user_db = model.User.get_by('auth_ids', auth_id)
  if user_db:
    return user_db
  return create_user_db(
      auth_id,
      response['name'],
      response.get('username', response['name']),
      response.get('email', ''),
      verified=bool(response.get('email', '')),
    )


###############################################################################
# Bitbucket
###############################################################################
bitbucket_oauth = oauth.OAuth()

app.config['BITBUCKET'] = dict(
    base_url='https://api.bitbucket.org/1.0/',
    request_token_url='https://bitbucket.org/api/1.0/oauth/request_token',
    access_token_url='https://bitbucket.org/api/1.0/oauth/access_token',
    authorize_url='https://bitbucket.org/api/1.0/oauth/authenticate',
    consumer_key=config.CONFIG_DB.bitbucket_key,
    consumer_secret=config.CONFIG_DB.bitbucket_secret,
  )

bitbucket = bitbucket_oauth.remote_app('bitbucket', app_key='BITBUCKET')
bitbucket_oauth.init_app(app)


@app.route('/_s/callback/bitbucket/oauth-authorized/')
def bitbucket_authorized():
  response = bitbucket.authorized_response()
  if response is None:
    return 'Access denied'

  flask.session['oauth_token'] = (
      response['oauth_token'],
      response['oauth_token_secret'],
    )
  me = bitbucket.get('user')
  user_db = retrieve_user_from_bitbucket(me.data['user'])
  return signin_user_db(user_db)


@bitbucket.tokengetter
def get_bitbucket_oauth_token():
  return flask.session.get('oauth_token')


@app.route('/signin/bitbucket/')
def signin_bitbucket():
  return signin_oauth(bitbucket)


def retrieve_user_from_bitbucket(response):
  auth_id = 'bitbucket_%s' % response['username']
  user_db = model.User.get_by('auth_ids', auth_id)
  if user_db:
    return user_db
  if response['first_name'] or response['last_name']:
    name = ' '.join((response['first_name'], response['last_name'])).strip()
  else:
    name = response['username']
  emails = bitbucket.get('users/%s/emails' % response['username'])
  email = ''.join([e['email'] for e in emails.data if e['primary']][0:1])
  return create_user_db(
      auth_id=auth_id,
      name=name,
      username=response['username'],
      email=email,
      verified=bool(email),
    )


###############################################################################
# Dropbox
###############################################################################
dropbox_oauth = oauth.OAuth()

app.config['DROPBOX'] = dict(
    base_url='https://www.dropbox.com/1/',
    request_token_params={},
    request_token_url=None,
    access_token_method='POST',
    access_token_url='https://api.dropbox.com/1/oauth2/token',
    authorize_url='https://www.dropbox.com/1/oauth2/authorize',
    consumer_key=model.Config.get_master_db().dropbox_app_key,
    consumer_secret=model.Config.get_master_db().dropbox_app_secret,
  )

dropbox = dropbox_oauth.remote_app('dropbox', app_key='DROPBOX')
dropbox_oauth.init_app(app)


@app.route('/_s/callback/dropbox/oauth-authorized/')
def dropbox_authorized():
  response = dropbox.authorized_response()
  if response is None:
    return 'Access denied: error=%s error_description=%s' % (
        flask.request.args['error'],
        flask.request.args['error_description'],
      )
  flask.session['oauth_token'] = (response['access_token'], '')
  me = dropbox.get('account/info')
  user_db = retrieve_user_from_dropbox(me.data)
  return signin_user_db(user_db)


@dropbox.tokengetter
def get_dropbox_oauth_token():
  return flask.session.get('oauth_token')


@app.route('/signin/dropbox/')
def signin_dropbox():
  return signin_oauth(dropbox, 'https')


def retrieve_user_from_dropbox(response):
  auth_id = 'dropbox_%s' % response['uid']
  user_db = model.User.get_by('auth_ids', auth_id)
  if user_db:
    return user_db

  return create_user_db(
      auth_id=auth_id,
      name=response['display_name'],
      username=response['display_name'],
    )


###############################################################################
# GitHub
###############################################################################
github_oauth = oauth.OAuth()

app.config['GITHUB'] = dict(
    base_url='https://api.github.com/',
    request_token_url=None,
    access_token_method='POST',
    access_token_url='https://github.com/login/oauth/access_token',
    authorize_url='https://github.com/login/oauth/authorize',
    consumer_key=config.CONFIG_DB.github_client_id,
    consumer_secret=config.CONFIG_DB.github_client_secret,
    request_token_params={'scope': 'user:email'},
  )

github = github_oauth.remote_app('github', app_key='GITHUB')
github_oauth.init_app(app)


@app.route('/_s/callback/github/oauth-authorized/')
def github_authorized():
  response = github.authorized_response()
  if response is None:
    return 'Access denied: error=%s' % flask.request.args['error']
  flask.session['oauth_token'] = (response['access_token'], '')
  me = github.get('user')
  user_db = retrieve_user_from_github(me.data)
  return signin_user_db(user_db)


@github.tokengetter
def get_github_oauth_token():
  return flask.session.get('oauth_token')


@app.route('/signin/github/')
def signin_github():
  return signin_oauth(github)


def retrieve_user_from_github(response):
  auth_id = 'github_%s' % str(response['id'])
  user_db = model.User.get_by('auth_ids', auth_id)
  if user_db:
    return user_db
  return create_user_db(
      auth_id,
      response.get('name', response.get('login')),
      response.get('login'),
      response.get('email', ''),
      verified=bool(response.get('email', '')),
    )


###############################################################################
# Instagram
###############################################################################
instagram_oauth = oauth.OAuth()

app.config['INSTAGRAM'] = dict(
    base_url='https://api.instagram.com/v1',
    request_token_url=None,
    access_token_url='https://api.instagram.com/oauth/access_token',
    access_token_method='POST',
    authorize_url='https://instagram.com/oauth/authorize/',
    consumer_key=model.Config.get_master_db().instagram_client_id,
    consumer_secret=model.Config.get_master_db().instagram_client_secret,
  )

instagram = instagram_oauth.remote_app('instagram', app_key='INSTAGRAM')
instagram_oauth.init_app(app)


@app.route('/_s/callback/instagram/oauth-authorized/')
def instagram_authorized():
  response = instagram.authorized_response()
  if response is None:
    flask.flash(u'You denied the request to sign in.')
    return flask.redirect(util.get_next_url())

  flask.session['oauth_token'] = (response['access_token'], '')
  user_db = retrieve_user_from_instagram(response['user'])
  return signin_user_db(user_db)


@instagram.tokengetter
def get_instagram_oauth_token():
  return flask.session.get('oauth_token')


@app.route('/signin/instagram/')
def signin_instagram():
  return signin_oauth(instagram)


def retrieve_user_from_instagram(response):
  auth_id = 'instagram_%s' % response['id']
  user_db = model.User.get_by('auth_ids', auth_id)
  if user_db:
    return user_db

  return create_user_db(
      auth_id=auth_id,
      name=response.get('full_name', '').strip() or response.get('username'),
      username=response.get('username'),
    )


###############################################################################
# LinkedIn
###############################################################################
linkedin_oauth = oauth.OAuth()

app.config['LINKEDIN'] = dict(
    base_url='https://api.linkedin.com/v1/',
    request_token_url=None,
    access_token_url='https://www.linkedin.com/uas/oauth2/accessToken',
    access_token_method='POST',
    authorize_url='https://www.linkedin.com/uas/oauth2/authorization',
    consumer_key=config.CONFIG_DB.linkedin_api_key,
    consumer_secret=config.CONFIG_DB.linkedin_secret_key,
    request_token_params={
        'scope': 'r_basicprofile r_emailaddress',
        'state': util.uuid(),
      },
  )

linkedin = linkedin_oauth.remote_app('linkedin', app_key='LINKEDIN')
linkedin_oauth.init_app(app)


@app.route('/_s/callback/linkedin/oauth-authorized/')
@linkedin.authorized_handler
def linkedin_authorized(response):
  if response is None:
    return 'Access denied: error=%s error_description=%s' % (
        flask.request.args['error'],
        flask.request.args['error_description'],
      )
  flask.session['access_token'] = (response['access_token'], '')
  fields = 'id,first-name,last-name,email-address'
  profile_url = '%speople/~:(%s)?oauth2_access_token=%s' % (
      linkedin.base_url, fields, response['access_token'],
    )
  result = urlfetch.fetch(
      profile_url,
      headers={'x-li-format': 'json', 'Content-Type': 'application/json'}
    )
  try:
    content = flask.json.loads(result.content)
  except ValueError:
    return "Unknown error: invalid response from LinkedIn"
  if result.status_code != 200:
    return 'Unknown error: status=%s message=%s' % (
        content['status'], content['message'],
      )
  user_db = retrieve_user_from_linkedin(content)
  return signin_user_db(user_db)


@linkedin.tokengetter
def get_linkedin_oauth_token():
  return flask.session.get('access_token')


@app.route('/signin/linkedin/')
def signin_linkedin():
  return signin_oauth(linkedin)


def retrieve_user_from_linkedin(response):
  auth_id = 'linkedin_%s' % response['id']
  user_db = model.User.get_by('auth_ids', auth_id)
  if user_db:
    return user_db
  full_name = ' '.join([response['firstName'], response['lastName']]).strip()
  return create_user_db(
      auth_id,
      full_name,
      response['emailAddress'] or full_name,
      response['emailAddress'],
    )


###############################################################################
# Odnoklassniki
###############################################################################
odnoklassniki_oauth = oauth.OAuth()

odnoklassniki = odnoklassniki_oauth.remote_app(
    'odnoklassniki',
    base_url='http://api.odnoklassniki.ru/',
    request_token_url=None,
    access_token_url='http://api.odnoklassniki.ru/oauth/token.do',
    authorize_url='http://www.odnoklassniki.ru/oauth/authorize',
    consumer_key=model.Config.get_master_db().odnoklassniki_app_id,
    consumer_secret=model.Config.get_master_db().odnoklassniki_app_secret,
    access_token_params={'grant_type': 'authorization_code'},
    access_token_method='POST'
)


def odnoklassniki_oauth_sig(data, client_secret):
  suffix = hashlib.md5(
      '{0:s}{1:s}'.format(data['access_token'], client_secret)
    ).hexdigest()
  check_list = sorted([
      '{0:s}={1:s}'.format(key, value)
      for key, value in data.items()
      if key != 'access_token'
    ])
  return hashlib.md5(''.join(check_list) + suffix).hexdigest()


@app.route('/_s/callback/odnoklassniki/oauth-authorized/')
@odnoklassniki.authorized_handler
def odnoklassniki_authorized(resp):
  if resp is None:
    return 'Access denied: reason=%s error=%s' % (
      flask.request.args['error_reason'],
      flask.request.args['error_description']
    )
  access_token = resp.get('access_token')
  if not access_token:
    return 'Access denied: reason=%s error=%s' % (
        resp.get('error_description', 'Unknown'),
        resp.get('error', 'Unknown'),
      )
  flask.session['oauth_token'] = (access_token, '')
  try:
    data = {
      'method': 'users.getCurrentUser',
      'application_key':
        model.Config.get_master_db().odnoklassniki_consumer_public,
      'access_token': access_token,
    }
    data['sig'] = odnoklassniki_oauth_sig(
        data, client_secret=odnoklassniki.consumer_secret
      )
    params = urllib.urlencode(data)
    url = odnoklassniki.base_url + 'fb.do'
    request = urllib2.Request(url, params)
    odnoklassniki_resp = json.loads(urllib2.urlopen(request).read())
    user_db = retrieve_user_from_odnoklassniki(odnoklassniki_resp)
  except:
    flask.flash(
      'Something went wrong with Twitter sign in. Please try again.',
      category='danger'
    )
    return flask.redirect(flask.url_for(
        'auth.signin', next=util.get_next_url())
      )
  return signin_user_db(user_db)


@odnoklassniki.tokengetter
def get_odnoklassniki_oauth_token():
    return flask.session.get('oauth_token')


@app.route('/signin/odnoklassniki/')
def signin_odnoklassniki():
  save_request_params()
  return odnoklassniki.authorize(
      callback=flask.url_for(
          'odnoklassniki_authorized',
          next=util.get_next_url(),
          _external=True,
        )
    )


def retrieve_user_from_odnoklassniki(response):
  auth_id = 'odnoklassniki_%s' % response['user_id']
  user_db = model.User.retrieve_one_by('auth_ids', auth_id)
  if user_db:
    return user_db

  return create_user_db(
      auth_id,
      response['name'],
    )


###############################################################################
# Reddit
###############################################################################
reddit_oauth = oauth.OAuth()

app.config['REDDIT'] = dict(
    base_url='https://oauth.reddit.com/api/v1/',
    request_token_url=None,
    access_token_url='https://ssl.reddit.com/api/v1/access_token',
    access_token_params={'grant_type': 'authorization_code'},
    access_token_method='POST',
    authorize_url='https://ssl.reddit.com/api/v1/authorize',
    consumer_key=model.Config.get_master_db().reddit_client_id,
    consumer_secret=model.Config.get_master_db().reddit_client_secret,
    request_token_params={'scope': 'identity', 'state': util.uuid()},
  )

reddit = reddit_oauth.remote_app('reddit', app_key='REDDIT')
reddit_oauth.init_app(app)


def reddit_handle_oauth2_response():
  access_args = {
      'code': flask.request.args.get('code'),
      'client_id': reddit.consumer_key,
      'redirect_uri': flask.session.get('%s_oauthredir' % reddit.name),
    }
  access_args.update(reddit.access_token_params)
  auth = 'Basic ' + b64encode(
      ('%s:%s' % (reddit.consumer_key, reddit.consumer_secret)).encode(
          'latin1')).strip().decode('latin1')
  response, content = reddit.http_request(
      reddit.expand_url(reddit.access_token_url),
      method=reddit.access_token_method,
      data=urls.url_encode(access_args),
      headers={
          'Authorization': auth,
          'User-Agent': config.USER_AGENT,
        },
    )
  data = oauth.parse_response(response, content)
  if response.code not in (200, 201):
    raise oauth.OAuthException(
        'Invalid response from %s' % reddit.name,
        type='invalid_response', data=data,
      )
  return data


reddit.handle_oauth2_response = reddit_handle_oauth2_response


@app.route('/_s/callback/reddit/oauth-authorized/')
def reddit_authorized():
  response = reddit.authorized_response()
  if response is None or flask.request.args.get('error'):
    return 'Access denied: error=%s' % (flask.request.args['error'])

  flask.session['oauth_token'] = (response['access_token'], '')
  me = reddit.request('me')
  user_db = retrieve_user_from_reddit(me.data)
  return signin_user_db(user_db)


@reddit.tokengetter
def get_reddit_oauth_token():
  return flask.session.get('oauth_token')


@app.route('/signin/reddit/')
def signin_reddit():
  return signin_oauth(reddit)


def retrieve_user_from_reddit(response):
  auth_id = 'reddit_%s' % response['id']
  user_db = model.User.get_by('auth_ids', auth_id)
  if user_db:
    return user_db

  return create_user_db(
      auth_id=auth_id,
      name=response['name'],
      username=response['name'],
    )


###############################################################################
# Stack Overflow
###############################################################################
stackoverflow_oauth = oauth.OAuth()

app.config['STACKOVERFLOW'] = dict(
    base_url='https://api.stackexchange.com/2.1/',
    request_token_url=None,
    access_token_url='https://stackexchange.com/oauth/access_token',
    access_token_method='POST',
    authorize_url='https://stackexchange.com/oauth',
    consumer_key=config.CONFIG_DB.stackoverflow_client_id,
    consumer_secret=config.CONFIG_DB.stackoverflow_client_secret,
    request_token_params={},
  )

stackoverflow = stackoverflow_oauth.remote_app('stackoverflow', app_key='STACKOVERFLOW')
stackoverflow_oauth.init_app(app)


@app.route('/_s/callback/stackoverflow/oauth-authorized/')
@stackoverflow.authorized_handler
def stackoverflow_authorized(response):
  if response is None:
    return 'Access denied: error=%s error_description=%s' % (
        flask.request.args['error'],
        flask.request.args['error_description'],
      )
  flask.session['oauth_token'] = (response['access_token'], '')
  me = stackoverflow.get('me',
      data={
          'site': 'stackoverflow',
          'access_token': response['access_token'],
          'key': config.CONFIG_DB.stackoverflow_key,
        }
    )
  if me.data.get('error_id'):
    return 'Error: error_id=%s error_name=%s error_description=%s' % (
        me.data['error_id'],
        me.data['error_name'],
        me.data['error_message'],
      )
  if not me.data.get('items') or not me.data['items'][0]:
    return 'Unknown error, invalid server response: %s' % me.data
  user_db = retrieve_user_from_stackoverflow(me.data['items'][0])
  return signin_user_db(user_db)


@stackoverflow.tokengetter
def get_stackoverflow_oauth_token():
  return flask.session.get('oauth_token')


@app.route('/signin/stackoverflow/')
def signin_stackoverflow():
  return signin_oauth(stackoverflow)


def retrieve_user_from_stackoverflow(response):
  auth_id = 'stackoverflow_%s' % response['user_id']
  user_db = model.User.get_by('auth_ids', auth_id)
  if user_db:
    return user_db
  return create_user_db(
      auth_id,
      response['display_name'],
      response['display_name'],
    )


###############################################################################
# VK
###############################################################################
vk_oauth = oauth.OAuth()

app.config['VK'] = dict(
    base_url='https://api.vk.com/',
    request_token_url=None,
    access_token_url='https://oauth.vk.com/access_token',
    authorize_url='https://oauth.vk.com/authorize',
    consumer_key=model.Config.get_master_db().vk_app_id,
    consumer_secret=model.Config.get_master_db().vk_app_secret,
  )

vk = vk_oauth.remote_app('vk', app_key='VK')
vk_oauth.init_app(app)


@app.route('/_s/callback/vk/oauth-authorized/')
@vk.authorized_handler
def vk_authorized(response):
  if response is None:
    return 'Access denied: error=%s error_description=%s' % (
        flask.request.args['error'],
        flask.request.args['error_description'],
      )
  access_token = response['access_token']
  flask.session['oauth_token'] = (access_token, '')
  me = vk.get('/method/getUserInfoEx', data={'access_token': access_token})
  user_db = retrieve_user_from_vk(me.data['response'])
  return signin_user_db(user_db)


@vk.tokengetter
def get_vk_oauth_token():
  return flask.session.get('oauth_token')


@app.route('/signin/vk/')
def signin_vk():
  return signin_oauth(vk)


def retrieve_user_from_vk(response):
  auth_id = 'vk_%s' % response['user_id']
  user_db = model.User.get_by('auth_ids', auth_id)
  if user_db:
    return user_db

  return create_user_db(
      auth_id,
      response['user_name'],
      response['user_name'],
    )


###############################################################################
# Microsoft
###############################################################################
microsoft_oauth = oauth.OAuth()

app.config['MICROSOFT'] = dict(
    base_url='https://apis.live.net/v5.0/',
    request_token_url=None,
    access_token_url='https://login.live.com/oauth20_token.srf',
    access_token_method='POST',
    authorize_url='https://login.live.com/oauth20_authorize.srf',
    consumer_key=model.Config.get_master_db().microsoft_client_id,
    consumer_secret=model.Config.get_master_db().microsoft_client_secret,
    request_token_params={'scope': 'wl.emails'},
  )

microsoft = microsoft_oauth.remote_app('microsoft', app_key='MICROSOFT')
microsoft_oauth.init_app(app)


@app.route('/_s/callback/microsoft/oauth-authorized/')
def microsoft_authorized():
  response = microsoft.authorized_response()
  if response is None:
    return 'Access denied: error=%s error_description=%s' % (
        flask.request.args['error'],
        flask.request.args['error_description'],
      )
  flask.session['oauth_token'] = (response['access_token'], '')
  me = microsoft.get('me')
  if me.data.get('error', {}):
    return 'Unknown error: error:%s error_description:%s' % (
        me['error']['code'],
        me['error']['message'],
      )
  user_db = retrieve_user_from_microsoft(me.data)
  return signin_user_db(user_db)


@microsoft.tokengetter
def get_microsoft_oauth_token():
  return flask.session.get('oauth_token')


@app.route('/signin/microsoft/')
def signin_microsoft():
  return signin_oauth(microsoft)


def retrieve_user_from_microsoft(response):
  auth_id = 'microsoft_%s' % response['id']
  user_db = model.User.get_by('auth_ids', auth_id)
  if user_db:
    return user_db
  email = response['emails']['preferred'] or response['emails']['account']
  return create_user_db(
      auth_id,
      response.get('name', ''),
      email,
      email,
      verified=bool(email),
    )


###############################################################################
# Yahoo!
###############################################################################
yahoo_oauth = oauth.OAuth()

app.config['YAHOO'] = dict(
    base_url='https://social.yahooapis.com/',
    request_token_url='https://api.login.yahoo.com/oauth/v2/get_request_token',
    access_token_url='https://api.login.yahoo.com/oauth/v2/get_token',
    authorize_url='https://api.login.yahoo.com/oauth/v2/request_auth',
    consumer_key=model.Config.get_master_db().yahoo_consumer_key,
    consumer_secret=model.Config.get_master_db().yahoo_consumer_secret,
  )

yahoo = yahoo_oauth.remote_app('yahoo', app_key='YAHOO')
yahoo_oauth.init_app(app)


@app.route('/_s/callback/yahoo/oauth-authorized/')
def yahoo_authorized():
  response = yahoo.authorized_response()
  if response is None:
    flask.flash(u'You denied the request to sign in.')
    return flask.redirect(util.get_next_url())

  flask.session['oauth_token'] = (
      response['oauth_token'],
      response['oauth_token_secret'],
    )

  try:
    yahoo_guid = yahoo.get(
        '/v1/me/guid',
        data={'format': 'json', 'realm': 'yahooapis.com'}
      ).data['guid']['value']

    profile = yahoo.get(
        '/v1/user/%s/profile' % yahoo_guid,
        data={'format': 'json', 'realm': 'yahooapis.com'}
      ).data['profile']
  except:
    flask.flash(
        u'Something went wrong with Yahoo! sign in. Please try again.',
        category='danger',
      )
    return flask.redirect(util.get_next_url())

  user_db = retrieve_user_from_yahoo(profile)
  return signin_user_db(user_db)


@yahoo.tokengetter
def get_yahoo_oauth_token():
  return flask.session.get('oauth_token')


@app.route('/signin/yahoo/')
def signin_yahoo():
  try:
    return signin_oauth(yahoo)
  except:
    flask.flash(
        u'Something went wrong with Yahoo! sign in. Please try again.',
        category='danger',
      )
    return flask.redirect(flask.url_for('signin', next=util.get_next_url()))


def retrieve_user_from_yahoo(response):
  auth_id = 'yahoo_%s' % response['guid']
  user_db = model.User.get_by('auth_ids', auth_id)
  if user_db:
    return user_db

  emails = [e for e in response.get('emails', []) if e.get('handle')]
  emails.sort(key=lambda e: e.get('primary', False))
  email = emails[0]['handle'] if emails else ''
  names = [response.get('givenName', ''), response.get('familyName', '')]
  return create_user_db(
      auth_id=auth_id,
      name=' '.join(names).strip() or response['nickname'],
      username=response['nickname'],
      email=email,
      verified=bool(email),
    )


###############################################################################
# Helpers
###############################################################################
def decorator_order_guard(f, decorator_name):
  if f in app.view_functions.values():
    raise SyntaxError(
        'Do not use %s above app.route decorators as it would not be checked. '
        'Instead move the line below the app.route lines.' % decorator_name
      )


def create_user_db(auth_id, name, username, email='', verified=False, **props):
  email = email.lower() if email else ''
  if verified and email:
    user_dbs, user_cr = model.User.get_dbs(email=email, verified=True, limit=2)
    if len(user_dbs) == 1:
      user_db = user_dbs[0]
      user_db.auth_ids.append(auth_id)
      user_db.put()
      task.new_user_notification(user_db)
      return user_db

  if isinstance(username, str):
    username = username.decode('utf-8')
  username = unidecode.unidecode(username.split('@')[0].lower()).strip()
  username = re.sub(r'[\W_]+', '.', username)
  new_username = username
  n = 1
  while not model.User.is_username_available(new_username):
    new_username = '%s%d' % (username, n)
    n += 1

  user_db = model.User(
      name=name,
      email=email,
      username=new_username,
      auth_ids=[auth_id] if auth_id else [],
      verified=verified,
      token=util.uuid(),
      **props
    )
  user_db.put()
  task.new_user_notification(user_db)
  return user_db


def save_request_params():
  flask.session['auth-params'] = {
      'next': util.get_next_url(),
      'remember': util.param('remember', bool),
    }


def signin_oauth(oauth_app, scheme='http'):
  flask.session.pop('oauth_token', None)
  save_request_params()
  return oauth_app.authorize(callback=flask.url_for(
      '%s_authorized' % oauth_app.name, _external=True, _scheme=scheme
    ))


def url_for_signin(service_name, next_url):
  return flask.url_for('signin_%s' % service_name, next=next_url)


@ndb.toplevel
def signin_user_db(user_db):
  if not user_db:
    return flask.redirect(flask.url_for('signin'))
  flask_user_db = FlaskUser(user_db)
  auth_params = flask.session.get('auth-params', {
      'next': flask.url_for('welcome'),
      'remember': False,
    })
  flask.session.pop('auth-params', None)
  if login.login_user(flask_user_db, remember=auth_params['remember']):
    user_db.put_async()
    flask.flash('Hello %s, welcome to %s.' % (
        user_db.name, config.CONFIG_DB.brand_name,
      ), category='success')
    return flask.redirect(util.get_next_url(auth_params['next']))
  flask.flash('Sorry, but you could not sign in.', category='danger')
  return flask.redirect(flask.url_for('signin'))
