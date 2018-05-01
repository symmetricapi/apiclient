import datetime

from django.utils import timezone

from apiclient import ApiClient, ApiClientAuthType, ApiClientPostType, ApiAction


__UTC = timezone.UTC()


def dropbox_timestamp_decoder(timestamp):
    """e.g. Sat, 21 Aug 2010 22:31:20 +0000"""
    try:
        return timezone.make_aware(datetime.datetime.strptime(timestamp, '%a, %d %b %Y %H:%M:%S %z'), __UTC)
    except:
        return None


class Dropbox(ApiClient):
    description = 'Dropbox API v2'
    type = 'DROPBOX'
    url = 'https://api.dropboxapi.com/2'
    post_type = ApiClientPostType.JSON
    auth_spec = {
        'type': ApiClientAuthType.OAUTH2,
        'authorize_url': 'https://www.dropbox.com/oauth2/authorize',
        'access_token_url': 'https://api.dropboxapi.com/oauth2/token',
        'refresh_url': '',
        'client_id': '',
        'client_secret': '',
        'scope': '',
        'include_secret': True,
        'deauthorize_url': 'https://api.dropboxapi.com/2/auth/token/revoke'
    }

    # Dropbox is an RPC interface so everything must go through POST
    def marshal(self, api_request, request):
        if api_request.resource_type == '?' and api_request.action == ApiAction.CREATE:
            request.headers['Dropbox-API-Arg'] = '{"path": "' + api_request.obj.external_path + '", "mute": true}'
            request.files = {'file': (api_request.obj.filename, api_request.obj.data)}
        elif api_request.action == ApiAction.READ:
            request.method = 'POST'
            # TODO: convert GET params into JSON POST data
