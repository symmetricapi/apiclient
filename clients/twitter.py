import datetime

from symmetric.views import ApiAction
from django.utils import timezone

from apiclient import ApiClient, ApiClientAuthType, ApiClientPostType, path_decoder, ApiError


__UTC = timezone.UTC()


def twitter_timestamp_decoder(timestamp):
    """Similar to a unix ctime but with a timezone added. e.g. Mon Sep 24 03:35:21 +0000 2012"""
    try:
        return timezone.make_aware(datetime.datetime.strptime(timestamp, '%a %b %d %H:%M:%S +0000 %Y'), __UTC)
    except:
        return None


def twitter_text_decoder(text):
    """Basic html decoding for <, >, and &"""
    # https://twittercommunity.com/t/tweet-text-html-encoding-clarity/68810/2
    if text.find('&') != -1:
        return text.replace('&gt;', '>').replace('&lt;', '<').replace('&amp;', '&')
    return text


class Twitter(ApiClient):
    description = 'Twitter API v1.1'
    type = 'TWITTER'
    url = 'https://api.twitter.com/1.1'
    post_type = ApiClientPostType.FORM
    auth_spec = {
        'type': ApiClientAuthType.OAUTH1,
        'request_token_url': 'https://api.twitter.com/oauth/request_token',
        'authorize_url': 'https://api.twitter.com/oauth/authorize',
        'access_token_url': 'https://api.twitter.com/oauth/access_token',
        'consumer_key': '',
        'consumer_secret': '',
    }

    def unmarshal(self, api_request, request, response):
        data = super(Twitter, self).unmarshal(api_request, request, response)
        if isinstance(data, dict):
            # data['search_metadata']['next_results'] will be missing if there is no next page
            has_next = data and data.get('search_metadata', {}).get('next_results')
            if 'statuses' in data:
                # https://dev.twitter.com/rest/public/timelines
                data = data.get('statuses', data)
                if has_next and len(data):
                    response.next_page = str(data[-1]['id'] - 1)
                    # response.prev_page = ???
        elif isinstance(data, list) and len(data):
            response.next_page = str(data[-1]['id'] - 1)
        return data

    def unmarshal_error(self, api_request, request, response):
        # https://dev.twitter.com/overview/api/response-codes
        data = super(Twitter, self).unmarshal(api_request, request, response)
        return ApiError(api_request, request, response, data['errors'][0]['code'], data['errors'][0]['message'])
