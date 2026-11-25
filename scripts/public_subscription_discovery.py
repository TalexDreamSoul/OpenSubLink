#!/usr/bin/env python3
"""Discover publicly published subscriptions and optionally sync to OpenSubLink.

Python 3.9+, standard library only. Run:
  python3 scripts/public_subscription_discovery.py --output /data/public-subscriptions.txt
Default output: ./data/public-subscriptions.txt (relative to current directory).
Optional GITHUB_TOKEN raises the public GitHub REST API rate limit.
Optional Google Programmable Search JSON API (GET https://www.googleapis.com/customsearch/v1):
set both GOOGLE_CSE_API_KEY and GOOGLE_CSE_ID. Missing/failed channels appear in
JSON output; exit 2 means degraded discovery/import, exit 1 means local/fatal failure.
Exit 0 means channels completed, not that any proxy is reachable. Output contains
counts and public repository identifiers, never subscription URLs, HTTP exception
text, credentials, or fetched content.
The default seeds are the public aiboboxx/v2rayfree repository and the
publisher's advertised ClashFree feed. Both still pass verification.
--no-seed disables both; --seed-repository OWNER/REPO replaces the repository.
Accept direct links published in public repository READMEs/manifests or on
public pages found by the optional web search. Never crawl a page recursively.
YAML verification deliberately accepts a conservative subset without executing
YAML tags, resolving aliases, or following nested provider references.

Optional OpenSubLink auto-import (idempotent airport sync by URL):
  OPENSUBLINK_BASE_URL (or SUBLINK_BASE_URL)   e.g. http://127.0.0.1:8000
  OPENSUBLINK_API_KEY  (or SUBLINK_API_KEY)    X-API-Key credential (never in argv)
  OPENSUBLINK_AUTO_IMPORT                      optional true/false override
  OPENSUBLINK_IMPORT_GROUP                     default: PublicDiscovery
  OPENSUBLINK_IMPORT_CRON                      default: 0 */6 * * *
  OPENSUBLINK_IMPORT_ENABLED                   default: true
  OPENSUBLINK_IMPORT_DETECT_PROFILE_ID         default: 0 (>0 enables post-pull check)
  OPENSUBLINK_IMPORT_PULL_EXISTING             default: false
  OPENSUBLINK_IMPORT_TIMEOUT                   default: 15 (seconds)
"""

import argparse
import base64
import concurrent.futures
import fcntl
import hashlib
from html.parser import HTMLParser
import http.client
import ipaddress
import json
import os
from pathlib import Path
import re
import socket
import ssl
import stat
import sys
import tempfile
import time
import urllib.parse

QUERIES = ("订阅 VLESS 公益节点", "白嫖 Clash 订阅", "public free Mihomo subscription")
DEFAULT_PUBLIC_FEED = 'https://clashfree.cc/sub/clash.yaml'
MAX_BODY = 3 * 1024 * 1024
LINK = re.compile(r'https?://[^\s<>\[\]"\'`]+', re.I)
PUBLIC = re.compile(r'公益|免费|公开|public|free|subscription|订阅', re.I)
PUBLIC_WEB = re.compile(r'公益|免费|公开|\bpublic\b|\bfree\b', re.I)
URI_PROTOCOLS = frozenset({
    'vmess', 'vless', 'trojan', 'ss', 'ssr',
    'hysteria', 'hysteria2', 'hy2', 'tuic', 'anytls', 'wireguard',
})
YAML_PROTOCOLS = URI_PROTOCOLS | frozenset({'socks', 'socks5', 'http', 'mieru', 'snell'})
PROTOCOLS = YAML_PROTOCOLS
NON_SUBSCRIPTION_EXTENSIONS = frozenset({
    '.md', '.markdown', '.rst', '.adoc',
    '.png', '.jpg', '.jpeg', '.gif', '.svg', '.ico', '.webp', '.bmp',
    '.pdf', '.zip', '.tar', '.gz', '.tgz', '.7z', '.rar', '.xz', '.bz2',
    '.exe', '.msi', '.dmg', '.pkg', '.apk', '.ipa', '.deb', '.rpm', '.appimage',
    '.css', '.js', '.mjs', '.map', '.woff', '.woff2', '.ttf', '.eot', '.otf',
    '.mp4', '.mp3', '.wav',
})
HTML_MARKER = re.compile(
    r'(?i)<!doctype\s+html'
    r'|<\s*/?\s*(?:html|head|body|title|meta|link|script|style|div|span|p|pre|code'
    r'|table|thead|tbody|tr|td|th|ul|ol|li|h[1-6]|section|article|header|footer|nav'
    r'|form|input|button|br)\b'
    r'|<\s*a\s+href\s*='
    r'|<\s*img\s+src\s*='
)
MARKDOWN_FENCE = re.compile(r'(?m)^[ \t]*(?:`{3,}|~{3,})')
MARKDOWN_HEADING = re.compile(r'(?m)^[ \t]*#{2,6}[ \t]+\S')
MARKDOWN_LINK_OR_IMAGE = re.compile(r'!?\[[^\]\n]{1,200}\]\(https?://[^\s)\n]+\)')
MARKDOWN_BLOCKQUOTE = re.compile(r'(?m)^[ \t]*>[ \t]+\S')
MARKDOWN_TABLE_LINE = re.compile(r'(?m)^[ \t]*\|.+\|[ \t]*$')
MARKDOWN_TABLE_DIVIDER = re.compile(
    r'(?m)^[ \t]*\|?[ \t]*:?-{3,}:?[ \t]*(?:\|[ \t]*:?-{3,}:?[ \t]*)+\|?[ \t]*$'
)
MARKDOWN_LIST_PROSE = re.compile(r'(?m)^[ \t]*[-*+][ \t]+(?:https?://|\S+[ \t]+\S+)')
YAML_TOP_LEVEL_KEY = re.compile(r'^(?:[A-Za-z0-9_.\-]+|"[^"\n]+"|\'[^\'\n]+\')[ \t]*:(?:[ \t]*(.*))?$')


class FetchError(Exception):
    pass


class OpenSubLinkImportError(Exception):
    pass


def public_address(host):
    addresses = socket.getaddrinfo(host, None, type=socket.SOCK_STREAM)
    if not addresses or any(not ipaddress.ip_address(a[4][0]).is_global for a in addresses):
        raise FetchError('non_public_host')
    return min(addresses, key=lambda address: address[0] != socket.AF_INET)[4][0]


def fetch(url, timeout=12, headers=None, maximum=MAX_BODY):
    """Pin validated DNS addresses, including every redirect; never use proxies."""
    deadline = time.monotonic() + timeout
    for _ in range(6):
        parts = urllib.parse.urlsplit(url)
        if parts.scheme not in ('http', 'https') or not parts.hostname or parts.username or parts.password:
            raise FetchError('invalid_url')
        port = parts.port or (443 if parts.scheme == 'https' else 80)
        if port not in (80, 443):
            raise FetchError('non_web_port')
        address = public_address(parts.hostname)
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise FetchError('timeout')
        connection = http.client.HTTPConnection(parts.hostname, port, timeout=remaining)
        try:
            connection.sock = socket.create_connection((address, port), remaining)
            if parts.scheme == 'https':
                connection.sock = ssl.create_default_context().wrap_socket(connection.sock, server_hostname=parts.hostname)
            transport = connection.sock
            request_headers = {'User-Agent': 'OpenSubLink-PublicDiscovery/1.0', 'Accept-Encoding': 'identity'}
            # Credentials are only ever attached to the original GitHub API host.
            if parts.hostname == 'api.github.com' and headers:
                request_headers.update(headers)
            connection.request('GET', urllib.parse.urlunsplit(('', '', parts.path or '/', parts.query, '')), headers=request_headers)
            response = connection.getresponse()
            if response.status in (301, 302, 303, 307, 308):
                location = response.getheader('Location')
                if not location:
                    raise FetchError('redirect_without_location')
                next_url = urllib.parse.urljoin(url, location)
                if parts.scheme == 'https' and urllib.parse.urlsplit(next_url).scheme != 'https':
                    raise FetchError('insecure_redirect')
                url = next_url
                continue
            if response.status != 200:
                raise FetchError('http_' + str(response.status))
            if response.getheader('Content-Encoding', 'identity').lower() not in ('', 'identity'):
                raise FetchError('unsupported_encoding')
            chunks, size = [], 0
            while True:
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    raise FetchError('timeout')
                transport.settimeout(remaining)
                chunk = response.read(min(65536, maximum + 1 - size))
                if not chunk:
                    return b''.join(chunks)
                chunks.append(chunk)
                size += len(chunk)
                if size > maximum:
                    raise FetchError('too_large')
        finally:
            connection.close()
    raise FetchError('too_many_redirects')


def decode64(value):
    return base64.b64decode(value + '=' * (-len(value) % 4), altchars=b'-_', validate=True)


def endpoint(host, port):
    digits = str(port)
    return isinstance(host, str) and bool(host.strip()) and digits.isascii() and digits.isdecimal() and 0 < int(digits) < 65536


def valid_uri(line):
    if not line or '://' not in line:
        return False
    before_fragment = line.split('#', 1)[0]
    if any(ch.isspace() for ch in before_fragment):
        return False
    try:
        scheme, payload = line.split('://', 1)
        scheme = scheme.lower()
        if scheme not in URI_PROTOCOLS:
            return False
        if scheme == 'vmess':
            node = json.loads(decode64(payload.split('#', 1)[0]).decode('utf-8'))
            return isinstance(node, dict) and endpoint(node.get('add'), node.get('port')) and bool(node.get('id'))
        if scheme == 'ssr':
            fields = decode64(payload.split('#', 1)[0]).decode('utf-8').split(':')
            return len(fields) >= 6 and endpoint(fields[0], fields[1])
        if scheme == 'ss' and '@' not in payload.split('#', 1)[0]:
            payload = decode64(payload.split('#', 1)[0]).decode('utf-8')
        parsed = urllib.parse.urlsplit(scheme + '://' + payload)
        if not endpoint(parsed.hostname, parsed.port):
            return False
        if parsed.username:
            return True
        if scheme == 'hysteria':
            query = urllib.parse.parse_qs(parsed.query)
            return bool(query.get('auth') or query.get('auth_str'))
        return False
    except (ValueError, TypeError, KeyError, UnicodeError):
        return False


def scalar(value):
    return value.strip().strip('\"\'')


def looks_like_html(text):
    return bool(HTML_MARKER.search(text))


def looks_like_markdown_document(text):
    return bool(
        MARKDOWN_FENCE.search(text)
        or MARKDOWN_HEADING.search(text)
        or MARKDOWN_LINK_OR_IMAGE.search(text)
        or MARKDOWN_BLOCKQUOTE.search(text)
        or MARKDOWN_TABLE_LINE.search(text)
        or MARKDOWN_TABLE_DIVIDER.search(text)
        or MARKDOWN_LIST_PROSE.search(text)
    )


def valid_uri_list(text):
    if not text or looks_like_html(text) or looks_like_markdown_document(text):
        return False
    non_empty = [line.strip() for line in text.splitlines() if line.strip()]
    if not non_empty:
        return False
    comment_lines = [line for line in non_empty if line.startswith('#')]
    content_lines = [line for line in non_empty if not line.startswith('#')]
    if not content_lines:
        return False
    valid_count = sum(1 for line in content_lines if valid_uri(line))
    if valid_count < 1:
        return False
    # Proxy URIs must form a clear majority (>= 60%) of non-comment lines so prose/READMEs
    # that happen to include sample node snippets are rejected.
    if valid_count * 5 < len(content_lines) * 3:
        return False
    if len(comment_lines) > max(3, valid_count):
        return False
    return True


def valid_clash_yaml_structure(text):
    """Verify top-level YAML structure so Markdown/HTML docs with `proxies:` blocks fail."""
    if looks_like_html(text) or MARKDOWN_FENCE.search(text) or MARKDOWN_TABLE_DIVIDER.search(text):
        return False
    seen_key = False
    allow_col0_seq = False
    for raw_line in text.splitlines():
        stripped = raw_line.strip()
        if not stripped or stripped.startswith('#'):
            continue
        if raw_line[0] in ' \t':
            if not seen_key:
                return False
            continue
        if stripped in ('---', '...'):
            continue
        if raw_line.startswith('- ') or stripped == '-':
            if not allow_col0_seq:
                return False
            continue
        match = YAML_TOP_LEVEL_KEY.match(raw_line)
        if not match:
            return False
        seen_key = True
        value_part = (match.group(1) or '').strip()
        allow_col0_seq = (not value_part) or value_part.startswith('#')
    return seen_key


def valid_clash_yaml(text):
    if not valid_clash_yaml_structure(text):
        return False
    section = re.search(r'^proxies:[ \t]*(?:#[^\n]*)?\r?\n', text, re.M)
    if not section:
        return False
    lines = []
    for line in text[section.end():].splitlines():
        if not line.strip() or line.lstrip().startswith('#'):
            continue
        if line[0] not in ' \t' and not line.startswith('- '):
            break
        lines.append(line)
    if not lines:
        return False
    first = re.match(r'^([ \t]*)-[ \t]+', lines[0])
    if not first:
        return False
    # Only split first-level sequence items. Collect the three needed scalars;
    # other fields may legitimately contain punctuation in their quoted values.
    items = re.split(r'(?m)^' + re.escape(first.group(1)) + r'-[ \t]+', '\n'.join(lines))
    for block in items[1:]:
        if block.lstrip().startswith(('!', '&', '*', '|', '>')):
            continue
        fields = {}
        for key, value in re.findall(r'(?:^|[\n,{])[ \t]*(type|server|port)[ \t]*:[ \t]*([^,}\n]+)', block.strip().strip('{}')):
            value = value.strip().split(' #', 1)[0]
            if not value.startswith(('!', '&', '*', '|', '>')):
                fields.setdefault(key, scalar(value))
        if fields.get('type') in YAML_PROTOCOLS and endpoint(fields.get('server'), fields.get('port')):
            return True
    return False


def valid_subscription(body):
    try:
        text = body.decode('utf-8-sig').strip()
    except UnicodeError:
        return False
    if not text or looks_like_html(text):
        return False
    if valid_uri_list(text):
        return True
    try:
        decoded = decode64(re.sub(r'\s+', '', text)).decode('utf-8').strip()
        if valid_uri_list(decoded):
            return True
    except (ValueError, UnicodeError):
        pass
    # JSON is also valid YAML, and common subscription publishers emit it.
    try:
        obj = json.loads(text)
        proxies = obj.get('proxies') if isinstance(obj, dict) else None
        return isinstance(proxies, list) and any(
            isinstance(n, dict)
            and isinstance(n.get('type'), str)
            and n['type'] in YAML_PROTOCOLS
            and endpoint(n.get('server'), n.get('port'))
            for n in proxies
        )
    except (ValueError, TypeError):
        pass
    return valid_clash_yaml(text)


def is_doc_or_asset_url(url):
    try:
        path = urllib.parse.unquote(urllib.parse.urlsplit(url).path or '').lower()
    except ValueError:
        return True
    basename = path.rsplit('/', 1)[-1]
    if basename.startswith('readme'):
        return True
    return any(path.endswith(ext) for ext in NON_SUBSCRIPTION_EXTENSIONS)


def github_json(path):
    headers = {'Accept': 'application/vnd.github+json', 'X-GitHub-Api-Version': '2022-11-28'}
    if os.environ.get('GITHUB_TOKEN'):
        headers['Authorization'] = 'Bearer ' + os.environ['GITHUB_TOKEN']
    return json.loads(fetch('https://api.github.com/' + path, headers=headers))


def candidate_url(value):
    value = value.rstrip(').,;，。')
    try:
        p = urllib.parse.urlsplit(value)
        if p.scheme not in ('http', 'https') or not p.hostname or p.username or p.password or p.fragment:
            return None
        # Reject obvious leaked/private credentials rather than publishing them.
        if re.search(r'(?:token|key|secret|password|auth|access|signature)=', p.query, re.I):
            return None
        if p.hostname == 'github.com':
            segments = p.path.split('/')
            if len(segments) > 5 and segments[3] == 'blob':
                raw_url = 'https://raw.githubusercontent.com/' + '/'.join(segments[1:3] + segments[4:])
                return None if is_doc_or_asset_url(raw_url) else raw_url
            return None
        if is_doc_or_asset_url(value):
            return None
        return value
    except ValueError:
        return None


class PublicPageLinks(HTMLParser):
    def __init__(self, url):
        super().__init__()
        self.url = url
        self.links = []

    def handle_starttag(self, tag, attrs):
        if tag == 'a':
            for key, value in attrs:
                if key == 'href' and value:
                    self.links.append(urllib.parse.urljoin(self.url, value))


def discover(args, report):
    repositories = {}
    pages = {}
    if not args.no_seed:
        if not re.fullmatch(r'[\w.-]+/[\w.-]+', args.seed_repository):
            raise FetchError('invalid_seed_repository')
        repositories[args.seed_repository] = 'HEAD'
    for query in QUERIES:
        try:
            result = github_json('search/repositories?' + urllib.parse.urlencode({'q': query, 'sort': 'updated', 'per_page': args.repositories}))
            for repo in result.get('items', []):
                if not repo.get('private') and re.fullmatch(r'[\w.-]+/[\w.-]+', repo.get('full_name', '')):
                    repositories.setdefault(repo['full_name'], repo.get('default_branch', 'HEAD'))
        except Exception as error:
            report['unavailable_channels'].append({'channel': 'github_search', 'reason': reason(error)})
    key, engine = os.environ.get('GOOGLE_CSE_API_KEY'), os.environ.get('GOOGLE_CSE_ID')
    if key and engine:
        for query in QUERIES:
            try:
                data = json.loads(fetch('https://www.googleapis.com/customsearch/v1?' + urllib.parse.urlencode({'key': key, 'cx': engine, 'q': query, 'num': 10})))
                for item in data.get('items', []):
                    p = urllib.parse.urlsplit(item.get('link', ''))
                    match = re.match(r'^/([\w.-]+/[\w.-]+)(?:/|$)', p.path)
                    if p.hostname == 'github.com' and match:
                        repositories.setdefault(match.group(1), 'HEAD')
                    elif candidate_url(item.get('link', '')) and PUBLIC_WEB.search(' '.join((item.get('title', ''), item.get('snippet', '')))):
                        pages.setdefault(item['link'], p.hostname)
            except Exception as error:
                report['unavailable_channels'].append({'channel': 'google_custom_search_json_api', 'reason': reason(error)})
    else:
        report['unavailable_channels'].append({'channel': 'google_custom_search_json_api', 'reason': 'not_configured' if not key and not engine else 'incomplete_configuration'})
    candidates = {}
    if not args.no_seed:
        candidates[DEFAULT_PUBLIC_FEED] = 'clashfree.cc'
    web_budget = max(1, args.max_candidates // 2)
    for url, publisher in list(pages.items())[:args.max_repositories]:
        try:
            body = fetch(url)
            text = body.decode('utf-8-sig')
            if not is_doc_or_asset_url(url) and valid_subscription(body):
                normalized = candidate_url(url)
                if normalized:
                    candidates.setdefault(normalized, publisher)
                continue
            if not PUBLIC_WEB.search(text):
                continue
            parser = PublicPageLinks(url)
            parser.feed(text)
            for value in parser.links + LINK.findall(text):
                normalized = candidate_url(value)
                if normalized:
                    candidates.setdefault(normalized, publisher)
                if len(candidates) >= web_budget:
                    break
            if len(candidates) >= web_budget:
                break
        except Exception:
            report['scan_warnings'] += 1
    for repo, branch in list(repositories.items())[:args.max_repositories]:
        try:
            tree = github_json('repos/' + repo + '/git/trees/' + urllib.parse.quote(branch, safe='') + '?recursive=1')
            if tree.get('truncated'):
                report['scan_warnings'] += 1
            entries = [entry for entry in tree.get('tree', []) if entry.get('type') == 'blob' and entry.get('size', 0) <= MAX_BODY and (re.search(r'(^|/)readme[^/]*$', entry['path'], re.I) or re.search(r'(?:subscribe|subscription|clash|mihomo|v2ray|nodes|manifest)[^/]*\.(?:ya?ml|json|txt)$', entry['path'], re.I))]
            entries.sort(key=lambda entry: (not bool(re.search(r'readme', entry['path'], re.I)), entry['path']))
            documents = []
            for entry in entries[:args.manifests]:
                path = urllib.parse.quote(entry['path'], safe='/')
                url = 'https://raw.githubusercontent.com/' + repo + '/' + urllib.parse.quote(branch, safe='') + '/' + path
                try:
                    blob = github_json('repos/' + repo + '/git/blobs/' + entry['sha'])
                    if blob.get('encoding') != 'base64':
                        raise FetchError('unsupported_github_encoding')
                    text = decode64(''.join(blob['content'].split())).decode('utf-8-sig')
                    documents.append((url, text))
                except Exception:
                    report['scan_warnings'] += 1
            # README must explicitly describe publicly available subscriptions.
            if not any(PUBLIC.search(text) for url, text in documents if re.search(r'readme', url, re.I)):
                continue
            for url, text in documents:
                # Never add README/doc blobs themselves as subscription candidates.
                if not is_doc_or_asset_url(url) and valid_subscription(text.encode('utf-8')):
                    candidates.setdefault(url, repo)
                for value in LINK.findall(text):
                    normalized = candidate_url(value)
                    if normalized:
                        candidates.setdefault(normalized, repo)
                    if len(candidates) >= args.max_candidates:
                        return candidates
        except Exception:
            report['repository_failures'] += 1
            report['scan_warnings'] += 1
    return dict(list(candidates.items())[:args.max_candidates])


def reason(error):
    if isinstance(error, (FetchError, OpenSubLinkImportError)):
        return str(error)
    return type(error).__name__


def parse_bool_env(value, default=False):
    if value is None or not str(value).strip():
        return default
    lowered = str(value).strip().lower()
    if lowered in ('1', 'true', 'yes', 'on'):
        return True
    if lowered in ('0', 'false', 'no', 'off'):
        return False
    return default


def resolve_import_config(args, env=None):
    env = os.environ if env is None else env
    if getattr(args, 'no_auto_import', False):
        return {'enabled_feature': False, 'status': 'disabled'}
    toggle_raw = env.get('OPENSUBLINK_AUTO_IMPORT')
    if toggle_raw is not None and toggle_raw.strip() and not parse_bool_env(toggle_raw, True):
        return {'enabled_feature': False, 'status': 'disabled'}
    base_url = (getattr(args, 'opensublink_url', None) or env.get('OPENSUBLINK_BASE_URL') or env.get('SUBLINK_BASE_URL') or '').strip()
    api_key = (env.get('OPENSUBLINK_API_KEY') or env.get('SUBLINK_API_KEY') or '').strip()
    explicit_enable = parse_bool_env(toggle_raw, False) or getattr(args, 'auto_import', False)
    if not base_url and not api_key:
        if explicit_enable:
            return {'enabled_feature': False, 'status': 'incomplete_configuration', 'reason': 'missing_base_url_and_api_key'}
        return {'enabled_feature': False, 'status': 'not_configured'}
    if not base_url:
        return {'enabled_feature': False, 'status': 'incomplete_configuration', 'reason': 'missing_base_url'}
    if not api_key:
        return {'enabled_feature': False, 'status': 'incomplete_configuration', 'reason': 'missing_api_key'}
    try:
        detect_profile_id = getattr(args, 'import_detect_profile_id', None)
        if detect_profile_id is None:
            detect_profile_id = int((env.get('OPENSUBLINK_IMPORT_DETECT_PROFILE_ID') or '0').strip() or '0')
    except ValueError:
        detect_profile_id = 0
    try:
        timeout = int((env.get('OPENSUBLINK_IMPORT_TIMEOUT') or '15').strip() or '15')
    except ValueError:
        timeout = 15
    return {
        'enabled_feature': True,
        'base_url': base_url.rstrip('/'),
        'api_key': api_key,
        'group': (getattr(args, 'import_group', None) or env.get('OPENSUBLINK_IMPORT_GROUP') or 'PublicDiscovery').strip(),
        'cron_expr': (getattr(args, 'import_cron', None) or env.get('OPENSUBLINK_IMPORT_CRON') or '0 */6 * * *').strip(),
        'airport_enabled': parse_bool_env(env.get('OPENSUBLINK_IMPORT_ENABLED'), True),
        'detect_profile_id': max(0, detect_profile_id),
        'pull_existing': bool(getattr(args, 'pull_existing', False) or parse_bool_env(env.get('OPENSUBLINK_IMPORT_PULL_EXISTING'), False)),
        'timeout': max(3, min(timeout, 120)),
    }


def opensublink_api_request(base_url, api_key, method, path, payload=None, timeout=15):
    """Call OpenSubLink REST API using X-API-Key without following redirects."""
    parts = urllib.parse.urlsplit(base_url)
    if parts.scheme not in ('http', 'https') or not parts.hostname or parts.username or parts.password or parts.fragment:
        raise OpenSubLinkImportError('invalid_base_url')
    port = parts.port or (443 if parts.scheme == 'https' else 80)
    base_path = parts.path.rstrip('/')
    request_path = base_path + (path if path.startswith('/') else '/' + path)
    headers = {
        'X-API-Key': api_key,
        'Accept': 'application/json',
        'User-Agent': 'OpenSubLink-PublicDiscovery/1.0',
    }
    body = None
    if payload is not None:
        body = json.dumps(payload, ensure_ascii=False).encode('utf-8')
        headers['Content-Type'] = 'application/json'
    if parts.scheme == 'https':
        connection = http.client.HTTPSConnection(parts.hostname, port, timeout=timeout, context=ssl.create_default_context())
    else:
        connection = http.client.HTTPConnection(parts.hostname, port, timeout=timeout)
    try:
        connection.request(method, request_path, body=body, headers=headers)
        response = connection.getresponse()
        raw = response.read(MAX_BODY)
        if response.status in (301, 302, 303, 307, 308):
            raise OpenSubLinkImportError('unexpected_redirect')
        if response.status != 200:
            raise OpenSubLinkImportError('http_' + str(response.status))
        try:
            envelope = json.loads(raw.decode('utf-8'))
        except (ValueError, UnicodeError) as error:
            raise OpenSubLinkImportError('invalid_json_response') from error
        if not isinstance(envelope, dict):
            raise OpenSubLinkImportError('invalid_envelope')
        code = envelope.get('code')
        if code != 200:
            raise OpenSubLinkImportError('api_code_' + str(code))
        return envelope.get('data')
    finally:
        connection.close()


def airport_name_for(url, source, existing_names):
    parts = urllib.parse.urlsplit(url)
    raw_label = (source or parts.hostname or 'public').strip()
    label = re.sub(r'[^A-Za-z0-9._/-]+', '-', raw_label).strip('-/') or (parts.hostname or 'public')
    digest = hashlib.sha256(url.encode('utf-8')).hexdigest()[:8]
    base = f'Public · {label[:40]} ({digest})'
    candidate = base
    suffix = 2
    while candidate in existing_names:
        candidate = f'{base}-{suffix}'
        suffix += 1
    return candidate


def sync_opensublink_airports(urls_with_sources, config, request_fn=opensublink_api_request):
    """Idempotently import verified public subscriptions as OpenSubLink airports."""
    summary = {
        'status': 'ok',
        'existing': 0,
        'imported': 0,
        'skipped_existing': 0,
        'pulled': 0,
        'failed': 0,
        'errors': [],
    }
    try:
        data = request_fn(
            config['base_url'],
            config['api_key'],
            'GET',
            '/api/v1/airports',
            payload=None,
            timeout=config['timeout'],
        )
    except Exception as error:
        summary['status'] = 'degraded'
        summary['failed'] = len(urls_with_sources)
        summary['errors'].append(reason(error))
        return summary

    if isinstance(data, dict) and isinstance(data.get('items'), list):
        items = data['items']
    elif isinstance(data, list):
        items = data
    else:
        summary['status'] = 'degraded'
        summary['failed'] = len(urls_with_sources)
        summary['errors'].append('unexpected_airport_list_shape')
        return summary

    existing_by_url = {}
    existing_names = set()
    for item in items:
        if not isinstance(item, dict):
            continue
        item_url = (item.get('url') or '').strip()
        if item_url:
            existing_by_url[item_url] = item
        item_name = (item.get('name') or '').strip()
        if item_name:
            existing_names.add(item_name)
    summary['existing'] = len(existing_by_url)

    seen_batch = set()
    for url, source in urls_with_sources:
        norm_url = url.strip()
        if not norm_url or norm_url in seen_batch:
            continue
        seen_batch.add(norm_url)
        if norm_url in existing_by_url:
            summary['skipped_existing'] += 1
            if config.get('pull_existing'):
                airport_id = existing_by_url[norm_url].get('id')
                if isinstance(airport_id, int) and airport_id > 0:
                    try:
                        request_fn(
                            config['base_url'],
                            config['api_key'],
                            'POST',
                            f'/api/v1/airports/{airport_id}/pull',
                            payload=None,
                            timeout=config['timeout'],
                        )
                        summary['pulled'] += 1
                    except Exception as error:
                        summary['failed'] += 1
                        summary['errors'].append(reason(error))
            continue

        name = airport_name_for(norm_url, source, existing_names)
        payload = {
            'name': name,
            'url': norm_url,
            'cronExpr': config['cron_expr'],
            'enabled': config['airport_enabled'],
            'group': config['group'],
            'remark': f'Auto-discovered public subscription ({source or "public"})',
            'autoFillCountry': True,
            'nodeNameUniquify': True,
        }
        if config.get('detect_profile_id', 0) > 0:
            payload['updateAfterDetect'] = True
            payload['updateAfterDetectProfileId'] = config['detect_profile_id']
            payload['updateAfterDetectChangedOnly'] = True
        try:
            request_fn(
                config['base_url'],
                config['api_key'],
                'POST',
                '/api/v1/airports',
                payload=payload,
                timeout=config['timeout'],
            )
            existing_by_url[norm_url] = {'name': name, 'url': norm_url}
            existing_names.add(name)
            summary['imported'] += 1
            # Enabled airports trigger an immediate pull inside OpenSubLink's POST /api/v1/airports.
            if config['airport_enabled']:
                summary['pulled'] += 1
        except Exception as error:
            summary['failed'] += 1
            summary['errors'].append(reason(error))

    if summary['failed'] > 0:
        summary['status'] = 'degraded'
    return summary


def append_atomic(output, additions):
    output.parent.mkdir(parents=True, exist_ok=True)
    # A persistent sibling lock serializes competing scheduled/manual invocations.
    with open(str(output) + '.lock', 'a', encoding='utf-8') as lock:
        fcntl.flock(lock, fcntl.LOCK_EX)
        original = output.read_text(encoding='utf-8') if output.exists() else ''
        seen = {line.strip() for line in original.splitlines() if line.strip()}
        new = []
        for url in additions:
            if url not in seen:
                new.append(url)
                seen.add(url)
        if not new:
            return 0
        content = original + ('\n' if original and not original.endswith('\n') else '') + '\n'.join(new) + '\n'
        descriptor, temporary = tempfile.mkstemp(prefix='.' + output.name + '.', dir=output.parent)
        try:
            mode = stat.S_IMODE(output.stat().st_mode) if output.exists() else 0o600
            os.fchmod(descriptor, mode)
            with os.fdopen(descriptor, 'w', encoding='utf-8', newline='\n') as stream:
                stream.write(content)
                stream.flush()
                os.fsync(stream.fileno())
            os.replace(temporary, output)
            directory = os.open(output.parent, os.O_RDONLY)
            try:
                os.fsync(directory)
            finally:
                os.close(directory)
        finally:
            if os.path.exists(temporary):
                os.unlink(temporary)
        return len(new)


def positive(value):
    number = int(value)
    if number < 1 or number > 1000:
        raise argparse.ArgumentTypeError('must be between 1 and 1000')
    return number


def non_negative(value):
    number = int(value)
    if number < 0 or number > 1000000:
        raise argparse.ArgumentTypeError('must be >= 0')
    return number


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument('--output', type=Path, default=Path('data/public-subscriptions.txt'))
    parser.add_argument('--seed-repository', default='aiboboxx/v2rayfree', help='public GitHub seed, verified through its README')
    parser.add_argument('--no-seed', action='store_true')
    parser.add_argument('--repositories', type=positive, default=5, help='results per GitHub query')
    parser.add_argument('--max-repositories', type=positive, default=6)
    parser.add_argument('--manifests', type=positive, default=4, help='maximum source files per repository')
    parser.add_argument('--max-candidates', type=positive, default=100)
    parser.add_argument('--workers', type=positive, default=4)
    parser.add_argument('--opensublink-url', default=None, help='OpenSubLink base URL for idempotent airport import (or set OPENSUBLINK_BASE_URL)')
    parser.add_argument('--auto-import', action='store_true', help='require OpenSubLink auto-import (uses OPENSUBLINK_BASE_URL + OPENSUBLINK_API_KEY)')
    parser.add_argument('--no-auto-import', action='store_true', help='disable OpenSubLink auto-import even when env vars are set')
    parser.add_argument('--import-group', default=None, help='airport group for auto-imported feeds (default: PublicDiscovery)')
    parser.add_argument('--import-cron', default=None, help='5-field cron schedule for auto-imported feeds (default: 0 */6 * * *)')
    parser.add_argument('--import-detect-profile-id', type=non_negative, default=None, help='node-check profile ID to trigger after airport pull (0=disabled)')
    parser.add_argument('--pull-existing', action='store_true', help='trigger manual pull for already-imported matching airports')
    args = parser.parse_args()
    report = {
        'output': str(args.output.absolute()),
        'candidates': 0,
        'verified': 0,
        'duplicates': 0,
        'additions': 0,
        'rejected': 0,
        'scan_warnings': 0,
        'repository_failures': 0,
        'unavailable_channels': [],
        'verified_sources': [],
        'node_connectivity_tested': False,
        'opensublink_import': {'status': 'not_configured'},
    }
    try:
        candidates = discover(args, report)
        report['candidates'] = len(candidates)

        def verify(url):
            try:
                return valid_subscription(fetch(url))
            except Exception:
                return False

        with concurrent.futures.ThreadPoolExecutor(max_workers=min(args.workers, 16)) as pool:
            results = list(pool.map(verify, candidates))
        verified = [url for url, accepted in zip(candidates, results) if accepted]
        report['verified'] = len(verified)
        report['rejected'] = len(candidates) - len(verified)
        report['verified_sources'] = [{'repository': candidates[url], 'candidate_sha256': hashlib.sha256(url.encode()).hexdigest()} for url in verified]
        report['additions'] = append_atomic(args.output, verified)
        report['duplicates'] = len(verified) - report['additions']

        import_cfg = resolve_import_config(args)
        if import_cfg.get('enabled_feature'):
            report['opensublink_import'] = sync_opensublink_airports(
                [(url, candidates[url]) for url in verified],
                import_cfg,
            )
        else:
            import_status = {'status': import_cfg['status']}
            if import_cfg.get('reason'):
                import_status['reason'] = import_cfg['reason']
            report['opensublink_import'] = import_status

        import_degraded = report['opensublink_import'].get('status') in ('degraded', 'incomplete_configuration')
        degraded = (
            any(item['reason'] != 'not_configured' for item in report['unavailable_channels'])
            or report['repository_failures'] > 0
            or import_degraded
        )
        report['status'] = 'degraded' if degraded else 'ok'
        print(json.dumps(report, ensure_ascii=False))
        return 2 if degraded else 0
    except Exception as error:
        report.update(status='error', error=reason(error))
        print(json.dumps(report, ensure_ascii=False))
        return 1


if __name__ == '__main__':
    sys.exit(main())
