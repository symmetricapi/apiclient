import datetime
import hmac
from hashlib import sha256

from symmetric.views import ApiAction
from django.utils import timezone

from apiclient import ApiClient, ApiClientAuthType, ApiClientPostType, path_decoder, ApiError, OAuthError


__UTC = timezone.UTC()


def instagram_timestamp_decoder(timestamp):
    """Parse the unix epoch timestamp."""
    try:
        return timezone.make_aware(datetime.datetime.utcfromtimestamp(int(timestamp)), __UTC)
    except:
        return None


class Instagram(ApiClient):
    description = 'Instagram API v1'
    type = 'INSTAGRAM'
    url = 'https://api.instagram.com/v1'
    post_type = ApiClientPostType.FORM
    auth_spec = {
        'type': ApiClientAuthType.OAUTH2,
        'authorize_url': 'https://api.instagram.com/oauth/authorize/',
        'implicit_url': 'https://instagram.com/oauth/authorize/?client_id=CLIENT-ID&redirect_uri=REDIRECT-URI&response_type=token',
        'access_token_url': 'https://api.instagram.com/oauth/access_token',
        'refresh_url': '',
        'client_id': '',
        'client_secret': '',
        'scope': '',
        'include_secret': True,
        'access_token_as_data': True
    }
    sign_requests = False

    @classmethod
    def _generate_sig(cls, endpoint, params):
        # In order to get better rate limits from securing api requests, all request must be
        # signed with the "Enforce signed requests" setting

        # https://instagram.com/developer/secure-api-requests/
        # Encode as utf-8 because some params might come from request data like a hashtag
        sig = endpoint
        for key in sorted(params.keys()):
            sig += '|%s=%s' % (key, params[key])
        return hmac.new(cls.auth_spec['client_secret'], sig.encode('utf-8'), sha256).hexdigest()

    def marshal(self, api_request, request):
        super(Instagram, self).marshal(api_request, request)
        if self.sign_requests:
            # Be sure to remove any existing signature from a previous request
            if request.params.get('sig'):
                del request.params['sig']
            endpoint = request.url[len(self.url):]
            params = {'access_token': self.session.auth.access_token}
            if api_request.action == ApiAction.READ or api_request.action == ApiAction.DELETE:
                params.update(request.params)
                request.params['sig'] = self._generate_sig(endpoint, params)
            else:
                params.update(request.data)
                request.data['sig'] = self._generate_sig(endpoint, params)

    def unmarshal(self, api_request, request, response):
        # http://instagram.com/developer/endpoints/
        data = super(Instagram, self).unmarshal(api_request, request, response)
        results = data.get('data', data)
        if data.get('pagination'):
            if api_request.endpoint == 'likes':
                response.next_page = data['pagination'].get('next_max_like_id')
                response.prev_page = data['pagination'].get('min_like_id')
            elif api_request.endpoint == 'usermedia' or api_request.endpoint == 'place':
                response.next_page = data['pagination'].get('next_max_id')
                response.prev_page = data['pagination'].get('min_id')
            else:
                response.next_page = data['pagination'].get('next_max_tag_id')
                response.prev_page = data['pagination'].get('min_tag_id')
        elif api_request.endpoint == 'geocode' and results:
            # Paging is done by timestamp with this endpoint and instagram
            # rounds to the nearest minute, so subtract 60 seconds
            # http://stackoverflow.com/questions/22348137/instagram-api-media-search-endpoint-return-results-outside-the-time-range
            response.next_page = int(results[-1]['created_time']) - 60
        return results

    def unmarshal_error(self, api_request, request, response):
        # Documentation indicates that a meta object contains the error response,
        # but in practice this isn't always true and error info is on the top-level
        # https://instagram.com/developer/endpoints/
        data = super(Instagram, self).unmarshal(api_request, request, response)
        if data and data.get('meta'):
            data = data['meta']
        if data['error_type'] in ('OAuthException', 'OAuthAccessTokenException', 'OAuthAccessTokenError'):
            return OAuthError(api_request, request, response, data['code'], data['error_message'])
        return ApiError(api_request, request, response, data['code'], data['error_message'])
