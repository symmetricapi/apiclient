from apiclient import ApiClient, ApiClientAuthType, ApiClientPostType, ApiError


class GooglePlus(ApiClient):
    description = 'Google + API'
    type = 'GOOGLE_PLUS'
    url = 'https://www.googleapis.com'
    post_type = ApiClientPostType.JSON
    # https://developers.google.com/identity/protocols/OAuth2WebServer - Click on HTTP/REST for the URLs
    # https://developers.google.com/+/web/api/rest/oauth.html - scope
    # https://developers.google.com/+/web/api/rest/index
    auth_spec = {
        'type': ApiClientAuthType.OAUTH2,
        'authorize_url': 'https://accounts.google.com/o/oauth2/v2/auth',
        'access_token_url': 'https://www.googleapis.com/oauth2/v4/token',
        'refresh_url': 'https://www.googleapis.com/oauth2/v4/token',
        'client_id': '',
        'client_secret': '',
        'scope': 'profile email',
        'deauthorize_url': 'https://accounts.google.com/o/oauth2/revoke',
        'include_secret': True
    }

    def unmarshal_error(self, api_request, request, response):
        data = super(GooglePlus, self).unmarshal(api_request, request, response)
        return ApiError(api_request, request, response, data['error']['code'], data['error']['message'])
