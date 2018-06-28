import inspect
import json
import logging
import re
try:
    from urllib.parse import quote
except ImportError:
    from urllib import quote
from urlparse import parse_qs

from symmetric.functions import iso_8601_to_time, iso_8601_to_date, iso_8601_to_datetime, time_to_iso_8601, date_to_iso_8601, datetime_to_iso_8601, decode_int, decode_float, decode_bool, underscore_to_camel_case
from symmetric.models import get_related_model
from symmetric.response import render_data, render_error, set_response_headers
from symmetric.views import ApiAction
from django.conf import settings
from django.db import models
from django.http import HttpResponse
from django.shortcuts import redirect
from django.core.urlresolvers import reverse
from django.utils.http import urlencode
from django.views.decorators.clickjacking import xframe_options_exempt
from django.views.decorators.csrf import ensure_csrf_cookie
import requests
from requests.auth import AuthBase
from requests_oauthlib import OAuth1


"""
TODO:
OAUTH2 token refreshing
Do something useful with authorization errors on callback?
    In addition to the redirect arg added by ApiClient
    Instagram - error_reason: 'user_denied', error_description: 'The user denied your request.', error: 'access_denied'
    Twitter - denied: 'fB3NuZr4ZXQZU5CGhdVs2ilPkcuCffcP'
    Facebook - error_description: 'Permissions error', error_code: '200', error_reason: 'user_denied', error: 'access_denied'
    Tumblr - no extra args
"""


logger = logging.getLogger('api.client')


def urlquote(value):
    # No safe characters
    return quote(value, '')


class rawdict(dict):
    def __getattr__(self, name):
        if name in self:
            return self[name]

    def __setattr__(self, name, value):
        self[name] = value

    def __delattr__(self, name):
        del self[name]


MOBILE_USER_AGENT_RE = re.compile('iPhone|iPod|iPad|Android|Windows Phone', re.I)


class ApiClientAuthType(object):
    OAUTH1 = 1
    OAUTH2 = 2
    APIKEY = 3


class ApiClientPostType(object):
    """
    FORM - Post objects as normal form encoded data. This doesn't support encoding embedded objects
    JSON - Post objects as JSON.
    FORM_JSON - Post objects as form encoded data, but each top level key's value is JSON encoded.
    """
    FORM = 1
    JSON = 2
    FORM_JSON = 3


class OAuth2(AuthBase):
    def __init__(self, access_token, as_data=False):
        self.access_token = access_token
        self.as_data = as_data

    def __call__(self, request):
        """Authorization callback for adding the access_token to a PreparedRequest.

        See PreparedRequest.prepare() for how and when the auth object gets called
        https://github.com/kennethreitz/requests/blob/master/requests/models.py
        """
        if self.as_data:
            if request.method == 'GET' or request.method == 'HEAD' or request.method == 'DELETE':
                # Reprepare the request.url with additional params, combining with the existing params
                request.prepare_url(request.url, {'access_token': self.access_token})
            else:
                if request.headers['Content-Type'].startswith('application/json'):
                    # Modify the already prepared json data, assumes that body is a json object ending with a }
                    if request.body:
                        request.body = request.body[:-1] + ',"access_token":%s}' % json.dumps(self.access_token)
                    else:
                        request.body = '{"access_token":%s}' % json.dumps(self.access_token)
                else:
                    # Just add on to the already form-encoded prepared body
                    if request.body:
                        request.body += '&access_token=' + urlquote(self.access_token)
                    else:
                        request.body = 'access_token=' + urlquote(self.access_token)
        else:
            request.headers['Authorization'] = 'Bearer ' + self.access_token
        return request


class ApiKey(AuthBase):
    def __init__(self, apikey):
        self.apikey = apikey

    def __call__(self, request):
        # Simply reprepare the request.url with the additional apikey param
        request.prepare_url(request.url, {'apikey': self.apikey})
        return request


class ApiError(Exception):
    """An API error occurred."""
    def __init__(self, api_request, request, response, code, message):
        self.api_request = api_request
        self.request = request
        self.response = response
        self.code = code
        self._message = message
        super(ApiError, self).__init__(message)

    message = property(lambda self: self._message)

    def __str__(self):
        return 'Error %d: %s' % (self.code, self._message)

    def __repr__(self):
        return 'apiclient.ApiError(%r, %r, %r, %r, %r)' % (self.api_request, self.request, self.response, self.code, self._message)


class OAuthError(ApiError):
    """An OAuth error occurred."""


class ApiRequest(object):
    def __init__(self, action, obj=None, resource_type=None, params=None, filter=None, endpoint=None, raw=False):
        """Contains everything needed to make a request.

        Set obj to access a specific object.
        Set resource_type to access a collection.
        Set both obj and resource_type to access a related collection.
        """
        self.data = None
        self.action = action
        self.obj = obj
        self.resource_type = resource_type
        self.params = params
        self.filter = filter
        self.endpoint = endpoint
        self.raw = bool(raw)
        self.collection = (resource_type is not None)
        self.related = (obj and resource_type)
        # resource_type can be passed through raw argument
        if not isinstance(raw, bool) and not self.resource_type:
            self.resource_type = raw
        # Detect resource_type as the object's cls
        if obj and not self.resource_type:
            self.resource_type = obj.resource_type if raw else obj.__class__
        # If resource_type is not a class then force raw
        if self.resource_type and not obj and not inspect.isclass(self.resource_type):
            self.raw = True

    def __repr__(self):
        return 'apiclient.ApiRequest(%r, %r, %r, %r, %r, %r)' % (
            self.action, self.obj, self.resource_type,
            self.params, self.filter, self.endpoint
        )


def path_decoder(url):
    """Grab the last component of a url as the path."""
    components = url.split('/')
    if components[-1]:
        return components[-1]
    else:
        return components[-2]


def _passthrough(value):
        return value


def _field_decoder(field):
    if isinstance(field, models.IntegerField):
        return decode_int
    elif isinstance(field, models.FloatField):
        return decode_float
    elif isinstance(field, models.BooleanField):
        return decode_bool
    elif isinstance(field, models.DateTimeField):
        return iso_8601_to_datetime
    elif isinstance(field, models.TimeField):
        return iso_8601_to_time
    elif isinstance(field, models.DateField):
        return iso_8601_to_date
    return None


def _field_encoder(field):
    if isinstance(field, models.DateTimeField):
        return datetime_to_iso_8601
    elif isinstance(field, models.TimeField):
        return time_to_iso_8601
    elif isinstance(field, models.DateField):
        return date_to_iso_8601
    return None


class ApiClientMeta(type):
    """Meta class to process and expand actions in the spec.

    Action Spec keyed by resource class, if keyed with a string or anything else will be forced to raw request:
    path - the path for the API call, as passed through string.format, with access to the variables: account, obj, and params
        - path may also be a dict, keyed by ApiActions, where paths vary by the type of action being performed if the different actions do not share the same path
    collection_path - same as path, only for doing a READ requests only of collections of resources
        - may also be a dict, where keys match up to the endpoint field from the ApiRequest, 'default' is used if no endpoint is specified
    method - an optional dictionary mapping ApiActions to override the http method used, e.g. GET, PUT, etc
    attributes_map - a dictionary mapping attributes (including extras and analytics) of the remote resource with the django resource, use . for related objects, e.g. link.title
    attribute_encoders - a dictionary mapping of attributes to callables when encoding external data
    attribute_decoders - a dictionary mapping of attributes to callables when decoding external data

    Action specs can be nested to create related relationships, keyed again by resource type and the path arguments have access to a parent variable as well
    A top-level action spec with the key default, will override any settings specified in each action spec, nested or not.
    """
    # http://eli.thegreenplace.net/2011/08/14/python-metaclasses-by-example
    def __init__(cls, name, bases, dct):
        def _expand(name):
            if name.find('.') == -1:
                return name
            else:
                return tuple(name.split('.'))

        def _process(action_spec, defaults=None):
            for key, value in action_spec.items():
                if inspect.isclass(key):
                    # A mapped action_spec
                    value['resource_type'] = key
                    if defaults:
                        value.update(defaults)
                    _process(value, defaults)
                else:
                    # Expand attribute maps
                    if key == 'attributes_map':
                        action_spec[key] = {_expand(external): _expand(internal) for external, internal in value.items()}
                    elif key in ('attribute_decoders', 'attribute_encoders'):
                        action_spec[key] = {_expand(external): internal for external, internal in value.items()}
            # Create the attribute encoders and decoders
            attributes_map = action_spec.get('attributes_map')
            resource = action_spec.get('resource_type')
            if attributes_map and resource:
                if 'attribute_decoders' not in action_spec:
                    action_spec['attribute_decoders'] = {}
                if 'attribute_encoders' not in action_spec:
                    action_spec['attribute_encoders'] = {}
                for external, internal in attributes_map.items():
                    if type(internal) is tuple:
                        temp = resource
                        for attr in internal:
                            field = temp._meta.get_field(attr)
                            # Skip if a data field is found (loosely defined as having a default value of a dict)
                            # - default decoder and encoder should come up empty
                            if isinstance(field.default, dict):
                                break
                            if hasattr(field, 'related'):
                                temp = get_related_model(field)
                        decoder = _field_decoder(field)
                        if decoder:
                            action_spec['attribute_decoders'].setdefault(external, decoder)
                        encoder = _field_encoder(field)
                        if encoder:
                            action_spec['attribute_encoders'].setdefault(external, encoder)
                    else:
                        field = resource._meta.get_field(internal)
                        decoder = _field_decoder(field)
                        if decoder:
                            action_spec['attribute_decoders'].setdefault(external, decoder)
                        encoder = _field_encoder(field)
                        if encoder:
                            action_spec['attribute_encoders'].setdefault(external, encoder)
        if object not in bases and getattr(cls, 'spec', None):
            _process(cls.spec, cls.spec.get('defaults'))
        super(ApiClientMeta, cls).__init__(name, bases, dct)


class _Session(object):
    # Final callback settings
    JS_DATA = 'apiclient_js_data'
    JS_TOKEN = 'apiclient_js_token'
    REDIRECT = 'apiclient_redirect'
    # Temporary cross-request variables required for OAuth flow
    REQUEST_TOKEN = 'apiclient_request_token'
    REQUEST_SECRET = 'apiclient_request_secret'
    REDIRECT_URI = 'apiclient_redirect_uri'


@xframe_options_exempt
def popup_iframe_proxy(request):
    """
    An iframe proxy to do a social login on a third-party site without exposing the access-token.
    Alternatively, use an auth with the popup callback but without the access token.
    """
    platform = request.GET.get('platform')
    if not platform:
        return HttpResponse('No platform specified.', status=400)
    js = """<!DOCTYPE html><html><head><style type="text/css">html,body,div{width:100%%;height:100%%;margin:0;cursor:pointer;}</style></head>
    <body><div></div><script type="text/javascript">
    document.addEventListener('click', function() {
        var origin = location.origin || location.protocol + '//' + location.hostname + (location.port ? (':' + location.port) : '');
        window.open(origin + '/auth/' + '%s' + '/?redirect=popup&token=true', '', 'menubar=no,toolbar=no,location=no,status=no,resizable=yes,scrollbars=yes,top=50,left=100,width=400,height=500');
        window.addEventListener('storage', function(event) {
            if(event.key !== 'auth')
                return;
            var value = JSON.parse(event.newValue);
            delete value.accessToken;
            delete value.accessSecret;
            delete value.refreshToken;
            window.parent.postMessage(value, '*');
        });
        window.addEventListener('message', function(event) {
            if(event.origin !== origin)
                return;
            delete event.data.accessToken;
            delete event.data.accessSecret;
            delete event.data.refreshToken;
            window.parent.postMessage(event.data, '*');
        });
    });
    </script></body></html>
    """ % platform
    return HttpResponse(js)


@ensure_csrf_cookie
def popup_callback_view(request):
    """
    Handle front-end authorization or deauthorization inside a popup.
    Include setting the csrf token because this popup may have been started from an embedded (as 3rd party) iframe where
    the Set-Cookie header does not work until the user has clicked to open this and relax the security restrictions.

    Communicate through localStorage on IE due to too many postMessage bugs.
    The problem with localStorage events are:
        - Not cross-origin capable
        - They cannot be directed to a single window
        - Not supported in private/incognito mode
    Also use localStorage with Android Chrome because the opener is null see:
        https://bugs.chromium.org/p/chromium/issues/detail?id=630770
        https://bugs.chromium.org/p/chromium/issues/detail?id=136610
    Use setTimeout redirect for Android Browser because it doesn't actually do popups
        - mainWindow is null because there is no parent window to talk to
        - localStorage, postMessage, and window.close() will all do nothing
    From the opener script:
        The 'message' event listener can filter events with:
            var origin = location.origin || location.protocol + '//' + location.hostname + (location.port ? (':' + location.port) : '');
            if (event.origin !== origin) return;
        The 'storage' event listener should filter events with:
            if (event.key !== 'auth') return;
    """
    js = """<!DOCTYPE html><script type="text/javascript">
    function getHashParameters() {
        var loc = location.hash.replace(/\+/g, ' '), match = null, params = {};
        var re = /(#|&)(.+?)=(.*?)(?=&|$)/g;
        while((match = re.exec(loc)) !== null)
            params[decodeURIComponent(match[2])] = decodeURIComponent(match[3]);
        return params;
    }
    var mainWindow = window.opener || window.parent.opener;
    var windowName = window.name.replace('___', '://').replace('__', ':').replace(/_/g, '.');
    var targetOrigin = '%s';
    if(%s)
        targetOrigin = windowName;
    if(!mainWindow || /msie/i.exec(navigator.userAgent) || /trident/i.exec(navigator.userAgent))
        localStorage.setItem('auth', JSON.stringify(getHashParameters()));
    else
        mainWindow.postMessage(getHashParameters(), targetOrigin);
    window.close();
    setTimeout(function() { window.location.href = '%s'; }, 1000);
    </script>
    """
    # Post a message back to any window when debugging
    origin = '*' if settings.DEBUG else (request.scheme + '://' + request.get_host())
    # Allowed origins provides a cross-origin solution to authenticate with one
    # origin and pass the credentials to another origin
    # The parent window must pass its location.origin for the targetOrigin through using the
    # window.open name argument because the opener.location.origin is not readable in the popup
    # window.name must be encoded with ___ = ://, __ = :, _ = .
    # If something overwrites window.name it could cause a problem though,
    # so it is not a perfect solution, so a bit of a hack
    allowed_origins = getattr(settings, 'API_CLIENT_ALLOWED_ORIGINS', None)
    fallback_url = getattr(settings, 'API_CLIENT_POPUP_REDIRECT_FALLBACK', '/')
    if allowed_origins:
        allowed_origins = ["windowName === '%s'" % allowed for allowed in allowed_origins]
        allowed_origins = '||'.join(allowed_origins)
    else:
        allowed_origins = 'false'
    return HttpResponse(js % (origin, allowed_origins, fallback_url))


class AuthStorage(object):
    NONE = 0
    SESSION = 1
    DATABASE = 2


class ApiClient(object):
    """The following properties should be set on a subclass:

    Account - the account model to use
    type - the type to assign to the type field of a new Account
    post_type - method of posting, see ApiClientPostType, defaults to ApiClientPostType.FORM
    auth_spec - An authspec dictionary as described below
    description - A descriptive string describing this API client
    spec - The dictionary of specs
    url - Required url prefix for making api requests, e.g. https://api.example.com/

    OAuth1 Spec:

    type - ApiClientAuthType.OAUTH1
    request_token_url - url for getting a request token
    authorize_url - the authorize url to send the user agent
    access_token_url - the url to resolve a request token, secret, and verifier into an access token
    consumer_key - the app's consumer key for all requests
    consumer_secret - the app's consumer secret used for signing requests
    deauthorize_url - (optional) the deauthorize url to revoke access
    access_as_app - True if access can happen using app credentials
    mobile_authorization - detect mobile user agents and use the m subdomain version of the authorize_url so that a mobile app does not handle the auth and lose the cookies

    OAuth2 Spec:

    type - ApiClientAuthType.OAUTH2
    authorize_url - the authorize url to send the user agent
    access_token_url - the url to resolve a request code into an access token
    refresh_url - the url to resolve a refresh token into a new access token
    client_id - the app's client id for all requests
    client_secret - the app's client secret used for signing
    scope - the authorization scope to use with the authorize_url, a comma or space separated string
    include_secret - include the client_secret when getting an access_token, seems non-standard, maybe just something facebook does? https://developers.facebook.com/docs/facebook-login/manually-build-a-login-flow/v2.2
    refresh_token_as_code - if the refresh token is really a code and should be passed using a "code" param
    access_token_as_data - place the access_token into the query string or body instead of the Authorization header, seems non-standard, maybe just something facebook does?
    deauthorize_url - (optional) the deauthorize url to revoke access
    access_as_app - True if access can happen using app credentials
    mobile_authorization - detect mobile user agents and use the m subdomain version of the authorize_url so that a mobile app does not handle the auth and lose the cookies

    Notes on redirect_urls:

    For oauth1 platforms like twitter, they require entering a redirect url in the online setup, but it isn't actively checked against what is sent.
    For oauth2, the redirect_url sent to the access_token_url must match the one sent to the authorize_url
    """
    __metaclass__ = ApiClientMeta
    auth_spec = None
    description = None
    spec = None
    type = 0
    url = None
    post_type = ApiClientPostType.FORM
    Account = None

    _METHOD_DICT = {
        ApiAction.READ: 'GET',
        ApiAction.CREATE: 'POST',
        ApiAction.UPDATE: 'PUT',
        ApiAction.DELETE: 'DELETE'
    }

    def __init__(self, account):
        self.account = account
        self.session = requests.Session()
        self.session.auth = self.get_auth(account)

    def __str__(self):
        return self.description

    @classmethod
    def _map_attributes(cls, action_spec, obj):
        data = {}
        for external, internal in action_spec['attributes_map'].items():
            if type(internal) is tuple:
                value = obj
                for attr in internal:
                    value = getattr(value, attr)
            else:
                value = getattr(obj, internal)
            value = action_spec['attribute_encoders'].get(external, _passthrough)(value)
            if type(external) is tuple:
                temp = data
                for attr in external[:-1]:
                    if attr not in temp:
                        temp[attr] = {}
                    temp = temp[attr]
                temp[external[-1]] = value
            else:
                data[external] = value
        return data

    @classmethod
    def _unmap_attributes(cls, action_spec, data, obj):
        for external, internal in action_spec['attributes_map'].items():
            if type(external) is tuple:
                value = data
                for attr in external:
                    value = value.get(attr)
                    # Skip arrays by taking the first element.
                    # e.g. for getting stuff from Twitter responses like media urls
                    if isinstance(value, (tuple, list)):
                        value = value[0]
                    elif value is None:
                        break
            else:
                value = data.get(external)
            if value is None:
                continue
            value = action_spec['attribute_decoders'].get(external, _passthrough)(value)
            if type(internal) is tuple:
                # Go straight to an data dictionary or recurse through a series of one or more foreign keys
                if isinstance(getattr(obj, internal[0]), dict):
                    setattr(getattr(obj, internal[0]), internal[1], value)
                else:
                    temp = obj
                    for attr in internal[:-1]:
                        if not getattr(temp, attr):
                            field = temp.__class__._meta.get_field(attr)
                            setattr(temp, get_related_model(field)())
                        temp = getattr(temp, attr)
                    setattr(temp, internal[-1], value)
            else:
                setattr(obj, internal, value)

    def _perform_action(self, api_request):
        action_spec = self.spec.get(api_request.resource_type)
        if not action_spec:
            return None
        if api_request.related:
            action_spec = action_spec.get(api_request.resource_type)
            if not action_spec:
                return None

        method = None
        if 'method' in action_spec:
            method = action_spec['method'].get(api_request.action)
        if not method:
            method = self._METHOD_DICT[api_request.action]

        if api_request.collection:
            path = action_spec['collection_path']
            if type(path) is dict:
                path = path[api_request.endpoint or 'default']
        else:
            path = action_spec['path']
            if type(path) is dict:
                path = path[api_request.action]
        # Convert the path to unicode first because string.format()
        # can't handle unicode arguments but unicode.format() can
        path = unicode(path).format(account=self.account, obj=api_request.obj, params=api_request.params)
        url = self.url + path

        # Prepare the request
        request = requests.Request(method, url, params=api_request.params)
        if api_request.action != ApiAction.READ and api_request.action != ApiAction.DELETE:
            if api_request.raw:
                api_request.data = api_request.obj
            else:
                api_request.data = self._map_attributes(action_spec, api_request.obj)
        self.marshal(api_request, request)

        # Perform the request and unmarshal the response
        response = self.session.send(self.session.prepare_request(request))
        if response.status_code >= 400:
            # 401 and WWW-Authenticate ussually indicate token is expired
            # Refreshing and try again if successful
            if response.status_code == 401 and response.headers.get('WWW-Authenticate'):
                if self.refresh_auth(self.account):
                    self.session.auth = self.get_auth(self.account)
                    return self._perform_action(api_request)
            error = self.unmarshal_error(api_request, request, response)
            logger.error(error)
            raise error
        data = self.unmarshal(api_request, request, response)

        # Filter and unmap all of the attributes
        if api_request.collection:
            if api_request.raw and not api_request.filter:
                return data, getattr(response, 'next_page', None), getattr(response, 'prev_page', None)

            collection = []
            for item in data:
                if not api_request.filter or api_request.filter(self.account, api_request, item):
                    if api_request.raw:
                        obj = item
                    else:
                        obj = api_request.resource_type()
                        self._unmap_attributes(action_spec, item, obj)
                        if hasattr(self, 'unmap_data'):
                            self.unmap_data(self.account, api_request, item, obj)
                    collection.append(obj)
            return collection, getattr(response, 'next_page', None), getattr(response, 'prev_page', None)
        else:
            if api_request.raw:
                return data
            else:
                self._unmap_attributes(action_spec, data, api_request.obj)
                if hasattr(self, 'unmap_data'):
                    self.unmap_data(self.account, api_request, data, api_request.obj)
                return api_request.obj

    def read(self, obj=None, resource_type=None, params=None, filter=None, endpoint=None, raw=False):
        return self._perform_action(ApiRequest(ApiAction.READ, obj, resource_type, params, filter, endpoint, raw))

    def create(self, obj, params=None, raw=False):
        return self._perform_action(ApiRequest(ApiAction.CREATE, obj, None, params, raw=raw))

    def update(self, obj, params=None, raw=False):
        return self._perform_action(ApiRequest(ApiAction.UPDATE, obj, None, params, raw=raw))

    def delete(self, obj, params=None, raw=False):
        return self._perform_action(ApiRequest(ApiAction.DELETE, obj, None, params, raw=raw))

    def read_related(self, obj, resource_type, params=None, filter=None, raw=False):
        return self._perform_action(ApiRequest(ApiAction.READ, obj, resource_type, params, filter, None, raw))

    def create_related(self, related_obj, obj, params=None, raw=False):
        return self._perform_action(ApiRequest(ApiAction.CREATE, related_obj, obj, params))

    def read_many(self, min_items, max_pages, resource_type=None, params=None, filter=None, endpoint=None, raw=False):
        items = []
        page_count = 0
        while page_count < max_pages:
            collection, next_page, prev_page = self._perform_action(ApiRequest(ApiAction.READ, None, resource_type, params, filter, endpoint, raw))
            items.extend(collection)
            if len(items) >= min_items or not next_page:
                break
            params.set_page(next_page)
            page_count += 1
        return items, next_page, prev_page

    @classmethod
    def from_request(cls, request, allow_access_as_app=False):
        """
        Create a client instance from a request object, either by an account in the database or attached to the session.
        """
        try:
            return cls(cls.Account.objects.get(**cls.get_request_filters(request, type=cls.type)))
        except:
            if request.session.has_key(cls.__name__):
                return cls(cls.Account(**request.session[cls.__name__]))
            elif allow_access_as_app and cls.auth_spec.get('access_as_app', False):
                return cls(None)
        return None

    @classmethod
    def view(cls, request, resource_type, **kwargs):
        client = cls.from_request(request, True)
        if not client:
            return render_error(request, 'There was a problem accessing %s please activate or renew your authorization.' % cls.__name__, 401)

        if request.api_action == ApiAction.READ:
            try:
                # Single object
                if kwargs:
                    obj = lambda x: x
                    obj.resource_type = resource_type
                    for key, value in kwargs.items():
                        setattr(obj, key, value)
                    data = client.read(obj, params=request.GET.dict(), raw=True)
                    return render_data(request, data)
                # Collection
                data, next_page, prev_page = client.read(None, resource_type, request.GET.dict())
                if next_page:
                    set_response_headers(request, **{'X-Next-Page': next_page})
                if next_page:
                    set_response_headers(request, **{'X-Prev-Page': prev_page})
                return render_data(request, data)
            except Exception as e:
                return render_error(request, e.message, 500)
        else:
            # TODO: support other actions
            return render_error(request, 'Unsupported method', 405)

    @classmethod
    def authorize_view(cls, request, **kwargs):
        """
        Basic authorization view that redirects to the api server.
        Be sure redirect parameter is lowercase when token=true.
        """
        redirect_url = request.GET.get('redirect', request.META.get('HTTP_REFERER'))
        js_token = request.GET.get('token', '').lower() == 'true'
        js_data = js_token or request.GET.get('data', '').lower() == 'true'
        if redirect_url == 'popup':
            redirect_url = request.build_absolute_uri(reverse(popup_callback_view))
        if js_token:
            if not redirect_url or not redirect_url.startswith('%s://%s' % (request.scheme, request.get_host())):
                return HttpResponse('Cross-origin redirect prohibited for js token.', status=403)
        request.session[_Session.JS_DATA] = js_data
        request.session[_Session.JS_TOKEN] = js_token
        request.session[_Session.REDIRECT] = redirect_url
        # Build the callback URL - use a proxied origin if set and allowed in settings
        callback_url = None
        allowed_origins = getattr(settings, 'API_CLIENT_ALLOWED_ORIGINS', None)
        forwarded_host = request.META.get('HTTP_X_FORWARDED_HOST', '')
        if allowed_origins and forwarded_host:
            forwarded_origin = '{scheme}://{host}'.format(scheme=request.scheme, host=forwarded_host)
            if forwarded_origin in allowed_origins:
                callback_url = forwarded_origin + reverse(cls.callback_view)
        if not callback_url:
            callback_url = request.build_absolute_uri(reverse(cls.callback_view))
        return redirect(cls.get_auth_url(request, callback_url, **kwargs))

    @classmethod
    def callback_view(cls, request):
        """Basic authorization callback, with support for a redirect given in the redirect query param."""
        account = cls.get_auth_account(request)
        redirect_url = request.session[_Session.REDIRECT]
        if not account:
            return redirect(redirect_url)
        if request.user.is_anonymous():
            if request.session[_Session.JS_TOKEN]:
                storage = AuthStorage.NONE
            else:
                storage = AuthStorage.SESSION
        else:
            storage = AuthStorage.DATABASE
        redirect_url = cls.process_callback(request, account, storage, redirect_url)
        if hasattr(cls, 'setup_view'):
            return cls.setup_view(request, account, storage, redirect_url)
        return redirect(redirect_url)

    @classmethod
    def deauthorize_view(cls, request):
        """Basic deauthorization callback, with support for a redirect given in the redirect query param."""
        if cls.auth_spec.has_key('deauthorize_url'):
            client = cls.from_request(request)
            headers = {'Content-Type': 'application/json'} if client.post_type == ApiClientPostType.JSON else None
            client.session.post(client.auth_spec.deauthorize_url, headers=headers)
        # Remove any account attached to the session
        if request.session.has_key(cls.__name__):
            del request.session[cls.__name__]
            request.session.modified = True
        # Remove any matching account saved to the database
        try:
            cls.Account.objects.get(**cls.get_request_filters(request, type=cls.type)).delete()
        except:
            pass
        redirect_url = request.GET.get('redirect', request.META.get('HTTP_REFERER', '/'))
        if redirect_url == 'popup':
            redirect_url = request.build_absolute_uri(reverse(popup_callback_view))
        return redirect(redirect_url)

    @classmethod
    def cancel_setup(cls, request):
        """Canceling setup same as deauthorization without the redirect."""
        cls.deauthorize_view(request)

    @classmethod
    def get_auth(cls, account=None, **kwargs):
        """Get the requests auth object."""
        if cls.auth_spec['type'] == ApiClientAuthType.OAUTH1:
            if account:
                kwargs['resource_owner_key'] = account.access_token
                kwargs['resource_owner_secret'] = account.access_secret
            return OAuth1(cls.auth_spec['consumer_key'], cls.auth_spec['consumer_secret'], **kwargs)
        elif cls.auth_spec['type'] == ApiClientAuthType.OAUTH2:
            access_token = account.access_token if account else cls.auth_spec['client_id'] + '|' + cls.auth_spec['client_secret']
            return OAuth2(access_token, cls.auth_spec.get('access_token_as_data', False))
        elif cls.auth_spec['type'] == ApiClientAuthType.APIKEY:
            return ApiKey(account.access_token)
        else:
            return None

    @classmethod
    def refresh_auth(cls, account):
        """
        Refresh an access token and saves it.
        Returns True is successful and the request and be retried.
        NOTE: This function will not work for session-based credentials because request isn't accessible.
        """
        refresh_url = cls.auth_spec.get('refresh_url')
        if refresh_url and account.refresh_token and cls.auth_spec['type'] == ApiClientAuthType.OAUTH2:
            params = {
                'grant_type': 'refresh_token',
                'client_id': cls.auth_spec['client_id'],
            }
            if cls.auth_spec.get('refresh_token_as_code', False):
                params['code'] = account.refresh_token
            else:
                params['refresh_token'] = account.refresh_token
            if cls.auth_spec.get('include_secret', False):
                params['client_secret'] = cls.auth_spec['client_secret']
            response = requests.post(refresh_url, data=params)
            content_type = response.headers.get('content-type', '').lower()
            if content_type.startswith('application/json') or content_type.startswith('text/javascript'):
                credentials = response.json()
                account.access_token = credentials['access_token']
                account.refresh_token = credentials.get('refresh_token', '')
            else:
                credentials = parse_qs(response.content)
                account.access_token = credentials.get('access_token')[0]
                account.refresh_token = credentials.get('refresh_token', [''])[0]
            if account.id:
                account.save()
            return True
        return False

    @classmethod
    def get_auth_url(cls, request, callback_url, **kwargs):
        """Create the authorization url for the user to visit. Override this to return a custom authorization url."""
        auth_url = cls.auth_spec.get('authorize_url', '')
        if auth_url and cls.auth_spec.get('mobile_authorization') and MOBILE_USER_AGENT_RE.search(request.META.get('HTTP_USER_AGENT', '')):
            auth_url = auth_url.replace('//','//m.', 1)
        if cls.auth_spec['type'] == ApiClientAuthType.OAUTH1:
            # OAuth1, use the request token url to get a request token
            response = requests.post(cls.auth_spec['request_token_url'], auth=cls.get_auth(callback_uri=callback_url))
            credentials = parse_qs(response.content)
            request.session[_Session.REQUEST_TOKEN] = credentials.get('oauth_token')[0]
            request.session[_Session.REQUEST_SECRET] = credentials.get('oauth_token_secret')[0]
            return '%s?oauth_token=%s' % (auth_url, urlquote(request.session[_Session.REQUEST_TOKEN]))
        if cls.auth_spec['type'] == ApiClientAuthType.OAUTH2:
            request.session[_Session.REDIRECT_URI] = callback_url
            return '%s?client_id=%s&redirect_uri=%s&response_type=code&scope=%s' % (auth_url, urlquote(cls.auth_spec['client_id']), urlquote(callback_url), urlquote(cls.auth_spec['scope']))
        if cls.auth_spec['type'] == ApiClientAuthType.APIKEY:
            # There is no auth, just skip to the callback/setup
            return callback_url
        raise NotImplementedError

    @classmethod
    def get_auth_account(cls, request):
        """Override this to return an account from an authorization callback. Return None on an authorization error."""
        if cls.auth_spec['type'] == ApiClientAuthType.OAUTH1:
            if not request.GET.has_key('oauth_verifier'):
                del request.session[_Session.REQUEST_TOKEN]
                del request.session[_Session.REQUEST_SECRET]
                return None
            response = requests.post(cls.auth_spec['access_token_url'], auth=cls.get_auth(resource_owner_key=request.session[_Session.REQUEST_TOKEN], resource_owner_secret=request.session[_Session.REQUEST_SECRET], verifier=request.GET['oauth_verifier']))
            del request.session[_Session.REQUEST_TOKEN]
            del request.session[_Session.REQUEST_SECRET]
            credentials = parse_qs(response.content)
            account = cls.Account()
            account.access_token = credentials.get('oauth_token')[0]
            account.access_secret = credentials.get('oauth_token_secret')[0]
            cls(account).read(account)
            account.type = cls.type
            return account
        if cls.auth_spec['type'] == ApiClientAuthType.OAUTH2:
            if not request.GET.has_key('code'):
                del request.session[_Session.REDIRECT_URI]
                return None
            params = {'grant_type': 'authorization_code', 'code': request.GET['code'], 'redirect_uri': request.session[_Session.REDIRECT_URI], 'client_id': cls.auth_spec['client_id']}
            if cls.auth_spec.get('include_secret', False):
                params['client_secret'] = cls.auth_spec['client_secret']
            response = requests.post(cls.auth_spec['access_token_url'], data=params)
            del request.session[_Session.REDIRECT_URI]
            account = cls.Account()
            content_type = response.headers.get('content-type', '').lower()
            if content_type.startswith('application/json') or content_type.startswith('text/javascript'):
                credentials = response.json()
                account.access_token = credentials['access_token']
                account.refresh_token = credentials.get('refresh_token', '')
            else:
                credentials = parse_qs(response.content)
                account.access_token = credentials.get('access_token')[0]
                account.refresh_token = credentials.get('refresh_token', [''])[0]
            cls(account).read(account)
            account.type = cls.type
            return account
        if cls.auth_spec['type'] == ApiClientAuthType.APIKEY:
            # Just a blank account until setup
            account = cls.Account()
            account.type = cls.type
            return account
        raise NotImplementedError

    @classmethod
    def process_callback(cls, request, account, storage, redirect_url):
        """
        Process the new account and save into the specified storage and returning a redirect with requested js data.
        """

        # Prepare the account data
        account_data = {
            'type': account.type,
            'access_token': account.access_token,
            'access_secret': getattr(account, 'access_secret', ''),
            'refresh_token': getattr(account, 'refresh_token', ''),
            'name': getattr(account, 'name', ''),
            'username': getattr(account, 'username', ''),
            'uid': getattr(account, 'uid', ''),
            'profile_image': getattr(account, 'profile_image', '')
        }

        # Save to the storage
        if storage == AuthStorage.SESSION:
            # Create a copy of account_data into the session before it gets modified below
            request.session[cls.__name__] = dict(account_data)
            request.session.modified = True
        elif storage == AuthStorage.DATABASE:
            account.save()

        # Append account data if requested as URL hash parameters while removing existing parameters
        if request.session[_Session.JS_DATA]:
            if not request.session[_Session.JS_TOKEN]:
                del account_data['access_token']
                del account_data['access_secret']
                del account_data['refresh_token']
            if getattr(settings, 'API_CAMELCASE', True):
                account_data = {underscore_to_camel_case(key): value for key, value in account_data.items()}
            redirect_url = redirect_url.split('#')[0] + '#' + urlencode(account_data)

        # Return final url with requested data
        return redirect_url

    @classmethod
    def get_request_filters(cls, request, **filters):
        """
        Update and return the filters dict for matching the request.current_user's auth accounts.
        raise cls.Account.DoesNotExist when filters cannot be updated.
        """
        raise NotImplementedError

    def marshal(self, api_request, request):
        """
        Override and return get args, post data, and headers
        (content-type will default to json if not set and post data is not empty).
        """
        if api_request.action != ApiAction.READ and api_request.action != ApiAction.DELETE:
            if self.post_type == ApiClientPostType.FORM:
                request.data = api_request.data
            elif self.post_type == ApiClientPostType.FORM_JSON:
                if api_request.data:
                    request.data = {}
                    for key, value in api_request.data.items():
                        if isinstance(value, (dict, list, tuple)):
                            request.data[key] = json.dumps(value)
                        else:
                            request.data[key] = value
            else:
                # JSON
                request.json = api_request.data

    def unmarshal(self, api_request, request, response):
        """
        Return python dict, array, etc. data from the response.
        If not implemented with just extract json from the response.
        Optionally, attach next_page and prev_page keys to response.
        """
        try:
            if api_request.raw:
                return json.loads(response.text, object_hook=rawdict)
            return response.json()
        except ValueError as e:
            logger.error('{}: {}'.format(e.message, response.content))
            raise

    def unmarshal_error(self, api_request, request, response):
        """
        Return an ApiError or OAuthError with a code and message.
        If not implemented will just use the HTTP status_code and reason of the response.
        """
        return ApiError(api_request, request, response, response.status_code, response.reason)
