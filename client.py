"""Authenticated YAPD API client; credentials are never logged."""
import http.cookiejar
import json
import os
import pathlib
import ssl
import urllib.error
import urllib.request

csrf = None
opener = urllib.request.build_opener(urllib.request.ProxyHandler({}),
    urllib.request.HTTPSHandler(context=ssl.create_default_context(cafile=os.environ.get('YAPD_CA_FILE') or None)),
    urllib.request.HTTPCookieProcessor(http.cookiejar.CookieJar()))

def secret(name):
    path = os.environ.get(name + '_FILE')
    value = pathlib.Path(path).read_text().rstrip('\r\n') if path else os.environ.get(name, '')
    if not value:
        raise ValueError('Missing required secret ' + name)
    return value

def api(path, body=None, method=None):
    origin = os.environ['YAPD_BASE_URL'].rstrip('/')
    if not origin.startswith('https://'):
        raise ValueError('YAPD HTTPS is required for secure session cookies')
    headers = {'Origin': origin, 'Accept': 'application/json', 'Accept-Language': 'en-US'}
    if csrf:
        headers['x-yapd-csrf'] = csrf
    data = None
    if body is not None:
        data = json.dumps(body).encode()
        headers['Content-Type'] = 'application/json'
    request = urllib.request.Request(origin + '/api' + path, data=data, headers=headers, method=method)
    try:
        with opener.open(request, timeout=90) as response:
            raw = response.read()
        return json.loads(raw) if raw else {}
    except urllib.error.HTTPError as error:
        # Avoid response bodies, which can echo private configuration/inputs.
        raise RuntimeError(f'YAPD {request.get_method()} {path}: HTTP {error.code}') from None

def login():
    global csrf
    response = api('/session/login', {'password': secret('YAPD_PASSWORD')})
    if not response.get('authenticated'):
        raise RuntimeError('YAPD authentication failed')
    csrf = response['csrfToken']

def instances():
    result = api('/instances')
    if isinstance(result, list):
        return result
    for key in ('instances', 'data', 'items'):
        if isinstance(result.get(key), list):
            return result[key]
    raise ValueError('Unexpected YAPD instances response')
