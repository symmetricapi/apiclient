from apiclient import ApiClient, ApiClientAuthType, ApiClientPostType, ApiError


class Tumblr(ApiClient):
    description = 'Tumblr API v2'
    type = 'TUMBLR'
    url = 'https://api.tumblr.com/v2'
    post_type = ApiClientPostType.FORM
    auth_spec = {
        'type': ApiClientAuthType.OAUTH1,
        'request_token_url': 'https://www.tumblr.com/oauth/request_token',
        'authorize_url': 'https://www.tumblr.com/oauth/authorize',
        'access_token_url': 'https://www.tumblr.com/oauth/access_token',
        'consumer_key': '',
        'consumer_secret': '',
    }

    def unmarshal(self, api_request, request, response):
        # All Tumblr responses return "meta":{"status":200,"msg":"OK"} and "response": ...
        data = super(Tumblr, self).unmarshal(api_request, request, response)
        return data.get('response', data)

    def unmarshal_error(self, api_request, request, response):
        # https://www.tumblr.com/docs/en/api/v2#console
        data = super(Tumblr, self).unmarshal(api_request, request, response)
        return ApiError(api_request, request, response, data['meta']['status'], data['meta']['msg'])
