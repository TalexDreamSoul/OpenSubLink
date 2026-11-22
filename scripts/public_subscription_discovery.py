#!/usr/bin/env python3
"""Discover publicly published subscriptions without importing them.

Python 3.9+, standard library only. Run:
  python3 scripts/public_subscription_discovery.py --output /data/public-subscriptions.txt
Default output: ./data/public-subscriptions.txt (relative to current directory).
Optional GITHUB_TOKEN raises the public GitHub REST API rate limit.
Optional Google Programmable Search JSON API (GET https://www.googleapis.com/customsearch/v1):
set both GOOGLE_CSE_API_KEY and GOOGLE_CSE_ID. Missing/failed channels appear in
JSON output; exit 2 means degraded discovery, exit 1 means local/fatal failure.
Exit 0 means channels completed, not that any proxy is reachable. No timers or
imports are installed. Output contains counts and public repository identifiers,
never subscription URLs, HTTP exception text, credentials, or fetched content.
The default seeds are the public aiboboxx/v2rayfree repository and the
publisher's advertised ClashFree feed. Both still pass verification.
--no-seed disables both; --seed-repository OWNER/REPO replaces the repository.
Accept direct links published in public repository READMEs/manifests or on
public pages found by the optional web search. Never crawl a page recursively.
YAML verification deliberately accepts a conservative subset without executing
YAML tags, resolving aliases, or following nested provider references.
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
PROTOCOLS = {'ss', 'ssr', 'vmess', 'vless', 'trojan', 'hysteria', 'hysteria2', 'hy2', 'tuic', 'socks', 'socks5', 'http', 'wireguard', 'anytls', 'mieru', 'snell'}


class FetchError(Exception):
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
    try:
        scheme, payload = line.split('://', 1)
        scheme = scheme.lower()
        if scheme not in PROTOCOLS:
            return False
        if scheme == 'vmess':
            node = json.loads(decode64(payload).decode('utf-8'))
            return isinstance(node, dict) and endpoint(node.get('add'), node.get('port')) and bool(node.get('id'))
        if scheme == 'ssr':
            fields = decode64(payload).decode('utf-8').split(':')
            return len(fields) >= 6 and endpoint(fields[0], fields[1])
        if scheme == 'ss' and '@' not in payload:
            payload = decode64(payload.split('#', 1)[0]).decode('utf-8')
        parsed = urllib.parse.urlsplit(scheme + '://' + payload)
        return endpoint(parsed.hostname, parsed.port) and bool(parsed.username)
    except (ValueError, TypeError, KeyError, UnicodeError):
        return False


def scalar(value):
    return value.strip().strip('\"\'')


def valid_subscription(body):
    try:
        text = body.decode('utf-8-sig').strip()
    except UnicodeError:
        return False
    if any(valid_uri(line.strip()) for line in text.splitlines()):
        return True
    try:
        decoded = decode64(re.sub(r'\s+', '', text)).decode('utf-8')
        if any(valid_uri(line.strip()) for line in decoded.splitlines()):
            return True
    except (ValueError, UnicodeError):
        pass
    # JSON is also valid YAML, and common subscription publishers emit it.
    try:
        obj = json.loads(text)
        proxies = obj.get('proxies') if isinstance(obj, dict) else None
        return isinstance(proxies, list) and any(isinstance(n, dict) and isinstance(n.get('type'), str) and n['type'] in PROTOCOLS and endpoint(n.get('server'), n.get('port')) for n in proxies)
    except (ValueError, TypeError):
        pass
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
        if fields.get('type') in PROTOCOLS and endpoint(fields.get('server'), fields.get('port')):
            return True
    return False


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
                return 'https://raw.githubusercontent.com/' + '/'.join(segments[1:3] + segments[4:])
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
            if valid_subscription(body):
                candidates.setdefault(candidate_url(url), publisher)
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
                if valid_subscription(text.encode('utf-8')):
                    candidates.setdefault(url, repo)
                for value in LINK.findall(text):
                    normalized = candidate_url(value)
                    if normalized:
                        candidates.setdefault(normalized, repo)
                    if len(candidates) >= args.max_candidates:
                        return candidates
        except Exception as error:
            report['repository_failures'] += 1
            report['scan_warnings'] += 1
    return dict(list(candidates.items())[:args.max_candidates])


def reason(error):
    if isinstance(error, FetchError):
        return str(error)
    return type(error).__name__


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
    args = parser.parse_args()
    report = {'output': str(args.output.absolute()), 'candidates': 0, 'verified': 0, 'duplicates': 0, 'additions': 0, 'rejected': 0, 'scan_warnings': 0, 'repository_failures': 0, 'unavailable_channels': [], 'verified_sources': [], 'node_connectivity_tested': False}
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
        degraded = any(item['reason'] != 'not_configured' for item in report['unavailable_channels']) or report['repository_failures'] > 0
        report['status'] = 'degraded' if degraded else 'ok'
        print(json.dumps(report, ensure_ascii=False))
        return 2 if degraded else 0
    except Exception as error:
        report.update(status='error', error=reason(error))
        print(json.dumps(report, ensure_ascii=False))
        return 1


if __name__ == '__main__':
    sys.exit(main())
