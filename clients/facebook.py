from symmetric.views import ApiAction

from apiclient import ApiClient, ApiClientAuthType, ApiClientPostType, ApiError, OAuthError


class Facebook(ApiClient):
    description = 'Facebook Graph API v2.10'
    type = 'FACEBOOK'
    url = 'https://graph.facebook.com/v2.10'
    post_type = ApiClientPostType.FORM_JSON
    auth_spec = {
        'type': ApiClientAuthType.OAUTH2,
        'authorize_url': 'https://www.facebook.com/dialog/oauth',
        'access_token_url': 'https://graph.facebook.com/oauth/access_token',
        'refresh_url': 'https://graph.facebook.com/oauth',
        'client_id': '',
        'client_secret': '',
        'scope': '',
        'include_secret': True,
        'access_token_as_data': True,
        'access_as_app': True
    }

    # NOTE: url query string can be included in the path and requests will combine it with the extra params passed in
    # TODO: secure graph requests in marshal: https://developers.facebook.com/docs/graph-api/securing-requests
    # Remember that crypto function require byte strings not unicode

    @classmethod
    def get_auth_url(cls, request, callback_url, **kwargs):
        auth_url = super(Facebook, cls).get_auth_url(request, callback_url, **kwargs)
        if request.GET.get('redirect') == 'popup':
            return auth_url + '&display=popup'
        return auth_url

    def unmarshal(self, api_request, request, response):
        data = super(Facebook, self).unmarshal(api_request, request, response)
        if data.get('paging', {}).get('cursors'):
            # https://developers.facebook.com/docs/graph-api/using-graph-api/v2.2#paging
            response.next_page = data['paging']['cursors'].get('after')
            response.prev_page = data['paging']['cursors'].get('before')
        return data.get('data', data)

    def unmarshal_error(self, api_request, request, response):
        # For other fields returned: https://developers.facebook.com/docs/graph-api/using-graph-api/v2.2#errors
        data = super(Facebook, self).unmarshal(api_request, request, response)
        message = data['error'].get('error_user_msg', data['error']['message'])
        if data['error']['type'] == 'OAuthException':
            return OAuthError(api_request, request, response, data['error']['code'], message)
        return ApiError(api_request, request, response, data['error']['code'], message)
