"""Offline regression tests: python3 -m unittest discover -s scripts -p 'test_public_subscription_discovery.py'."""

import argparse
import base64
from http.server import BaseHTTPRequestHandler, HTTPServer
import json
from pathlib import Path
import stat
import tempfile
import threading
import unittest

import public_subscription_discovery as discovery


def encoded(text):
    return base64.b64encode(text.encode('utf-8')).decode('ascii')


class ValidSubscriptionTests(unittest.TestCase):
    def test_accepts_structural_subscription_encodings(self):
        uri = 'vless://test-user@node.example:443?security=tls#Example'
        vmess = 'vmess://' + encoded(json.dumps({
            'add': 'node.example', 'port': '443', 'id': 'test-user',
        }))
        trojan = 'trojan://secret-pass@node.example:443#Trojan'
        ss = 'ss://' + encoded('aes-256-gcm:test-password@node.example:8388')
        ss_sip002 = 'ss://' + encoded('aes-256-gcm:test-password') + '@node.example:8388#SS'
        ssr = 'ssr://' + encoded('node.example:8388:origin:aes-256-cfb:plain:cGFzcw')
        hysteria = 'hysteria://node.example:443?auth=secret&peer=node.example#Hy1'
        hysteria2 = 'hysteria2://secret-pass@node.example:443?sni=node.example#Hy2'
        hy2 = 'hy2://secret-pass@node.example:443#Hy2Short'
        tuic = 'tuic://uuid:pass@node.example:443#Tuic'
        anytls = 'anytls://secret-pass@node.example:443#AnyTLS'
        wireguard = 'wireguard://private-key@node.example:51820?publickey=pub#WG'
        wrapped = encoded(uri + '\n' + ss).rstrip('=')
        cases = [
            ('plain_uri_list', ('# public nodes\ninvalid node\n' + uri + '\n' + ss).encode()),
            ('utf8_bom', ('\ufeff' + uri + '\n').encode('utf-8')),
            ('vmess_json_payload', vmess.encode()),
            ('trojan_uri', trojan.encode()),
            ('shadowsocks_base64_payload', ss.encode()),
            ('shadowsocks_sip002_payload', ss_sip002.encode()),
            ('shadowsocksr_base64_payload', ssr.encode()),
            ('hysteria_v1_uri', hysteria.encode()),
            ('hysteria2_uri', hysteria2.encode()),
            ('hy2_uri', hy2.encode()),
            ('tuic_uri', tuic.encode()),
            ('anytls_uri', anytls.encode()),
            ('wireguard_uri', wireguard.encode()),
            ('base64_uri_list', encoded(uri + '\n' + vmess).encode()),
            ('base64_unpadded_with_whitespace', ('\n' + '\n '.join(
                wrapped[index:index + 19] for index in range(0, len(wrapped), 19)
            ) + '\n').encode()),
            ('json_proxies', json.dumps({'proxies': [
                {'name': 'invalid', 'type': 'vless', 'server': '', 'port': 443},
                {'name': 'Example', 'type': 'trojan', 'server': 'node.example', 'port': 443},
            ]}).encode()),
            ('yaml_block_mapping', b'proxies:\n'
             b'  - name: Example\n'
             b'    type: vless\n'
             b'    server: node.example\n'
             b'    port: 443\n'),
            ('yaml_col0_sequence_items', b'# clashfree.cc public feed\n'
             b'mixed-port: 7890\n'
             b'proxies:\n'
             b'- name: HK 01 | clashfree.cc\n'
             b'  type: hysteria2\n'
             b'  server: node.example\n'
             b'  port: 443\n'),
            ('yaml_flow_mapping', b'proxies: # public nodes\n'
             b'  - {name: Example, type: ss, server: node.example, port: 8388}\n'),
            ('yaml_quoted_scalars', b'proxies:\n'
             b'  - name: "Example"\n'
             b'    type: "trojan"\n'
             b"    server: 'node.example'\n"
             b'    port: "443" # web port\n'),
        ]
        for name, body in cases:
            with self.subTest(name=name):
                self.assertTrue(discovery.valid_subscription(body))

    def test_rejects_markdown_html_and_prose_with_embedded_nodes(self):
        sample_uri = 'vless://test-user@node.example:443?security=tls#Example'
        sample_ss = 'ss://' + encoded('aes-256-gcm:test-password') + '@203.0.113.10:19999#SS-01'
        aiboboxx_like_readme = (
            '# 最新公益免费节点订阅地址每日更新\n'
            '## 免费节点及订阅地址：\n\n'
            '> 优质节点每天实时测速更新，6小时更新一次\n\n'
            '### 免费节点列表：\n\n'
            '```\n'
            + '\n'.join([sample_ss, sample_uri, sample_ss]) + '\n'
            '```\n\n'
            '### 永久订阅地址\n\n'
            '- https://raw.githubusercontent.com/free-nodes/v2rayfree/main/sub\n\n'
            '| 客户端 | 下载 |\n'
            '| --- | --- |\n'
            '| **V2rayN** | [GitHub](https://github.com/2dust/v2rayN/releases) |\n'
        )
        markdown_fenced_yaml = (
            '# Free Clash Config\n\n'
            '```yaml\n'
            'proxies:\n'
            '  - name: Example\n'
            '    type: vless\n'
            '    server: node.example\n'
            '    port: 443\n'
            '```\n'
        )
        markdown_prose_yaml = (
            '# Free Clash Config\n\n'
            'Copy the snippet below into Clash:\n'
            'proxies:\n'
            '  - name: Example\n'
            '    type: vless\n'
            '    server: node.example\n'
            '    port: 443\n'
        )
        html_with_uris = (
            '<!DOCTYPE html><html><body><pre>\n'
            + sample_uri + '\n' + sample_ss + '\n'
            '</pre></body></html>'
        )
        html_with_yaml = (
            '<html><body><pre>\n'
            'proxies:\n'
            '  - name: Example\n'
            '    type: ss\n'
            '    server: node.example\n'
            '    port: 443\n'
            '</pre></body></html>'
        )
        prose_with_one_uri = (
            'Updated daily for educational testing.\n'
            'Paste this link into your client:\n'
            + sample_uri + '\n'
        )
        cases = [
            ('markdown_readme_with_fenced_uris', aiboboxx_like_readme.encode('utf-8')),
            ('base64_encoded_markdown_readme', encoded(aiboboxx_like_readme).encode('ascii')),
            ('markdown_fenced_yaml', markdown_fenced_yaml.encode('utf-8')),
            ('markdown_prose_before_yaml', markdown_prose_yaml.encode('utf-8')),
            ('html_wrapping_valid_uris', html_with_uris.encode('utf-8')),
            ('base64_encoded_html_uris', encoded(html_with_uris).encode('ascii')),
            ('html_wrapping_valid_yaml', html_with_yaml.encode('utf-8')),
            ('plain_prose_with_sample_uri', prose_with_one_uri.encode('utf-8')),
            ('markdown_link_and_uri', ('[Sponsor](https://example.com)\n' + sample_uri).encode('utf-8')),
            ('http_uri_not_proxy_scheme', b'http://user@node.example:8080\n'),
            ('uri_with_trailing_prose', (sample_uri.split('#')[0] + ' extra prose words\n').encode('utf-8')),
        ]
        for name, body in cases:
            with self.subTest(name=name):
                self.assertFalse(discovery.valid_subscription(body))

    def test_rejects_malformed_or_non_node_content(self):
        cases = [
            ('empty', b''),
            ('whitespace', b' \r\n\t'),
            ('invalid_utf8', b'\xff\xfe\x80'),
            ('html_error_page', b'<html><body>Subscription temporarily unavailable</body></html>'),
            ('base64_prose', encoded('This is a public subscription page, without nodes.').encode()),
            ('invalid_base64', b'%%%not-base64%%%'),
            ('malformed_json', b'{"proxies": ['),
            ('json_array_instead_of_config', b'[{"type":"ss","server":"node.example","port":443}]'),
            ('json_null_proxies', b'{"proxies":null}'),
            ('json_non_node_entries', b'{"proxies":[null,42,"vless://node.example:443"]}'),
            ('json_unknown_protocol', b'{"proxies":[{"type":"invalid","server":"node.example","port":443}]}'),
            ('json_missing_server', b'{"proxies":[{"type":"ss","port":443}]}'),
            ('json_boolean_port', b'{"proxies":[{"type":"ss","server":"node.example","port":true}]}'),
            ('yaml_no_nodes', b'proxy-groups:\n  - name: Example\n    type: select\n    proxies: [DIRECT]\n'),
            ('yaml_missing_server', b'proxies:\n  - type: ss\n    port: 443\n'),
            ('yaml_tag', b'proxies:\n  - type: !!str ss\n    server: node.example\n    port: 443\n'),
            ('yaml_anchor', b'proxies:\n  - &node\n    type: ss\n    server: node.example\n    port: 443\n'),
            ('yaml_alias', b'proxies:\n  - type: ss\n    server: *host\n    port: 443\n'),
            ('yaml_multiline', b'proxies:\n  - type: ss\n    server: |\n      node.example\n    port: 443\n'),
            ('unknown_uri_protocol', b'ftp://user@node.example:443'),
            ('uri_missing_identity', b'vless://node.example:443'),
            ('uri_missing_host', b'vless://user@:443'),
            ('uri_missing_port', b'vless://user@node.example'),
            ('uri_nonnumeric_port', b'vless://user@node.example:abc'),
            ('vmess_invalid_base64', b'vmess://%%%'),
            ('vmess_invalid_json', ('vmess://' + encoded('{')).encode()),
            ('vmess_missing_identity', ('vmess://' + encoded(json.dumps({
                'add': 'node.example', 'port': 443,
            }))).encode()),
            ('ss_invalid_payload', ('ss://' + encoded('missing-endpoint')).encode()),
            ('ssr_incomplete_fields', ('ssr://' + encoded('node.example:8388:origin')).encode()),
        ]
        for name, body in cases:
            with self.subTest(name=name):
                self.assertFalse(discovery.valid_subscription(body))

    def test_rejects_vmess_json_values_that_are_not_node_mappings(self):
        for value in (None, [], ['node.example', 443], 'node.example', 443, True):
            with self.subTest(value=value):
                body = ('vmess://' + encoded(json.dumps(value))).encode()
                self.assertFalse(discovery.valid_subscription(body))

    def test_requires_port_in_valid_range_across_encodings(self):
        for port, expected in ((-1, False), (0, False), (1, True),
                               (65535, True), (65536, False)):
            node = {'type': 'ss', 'server': 'node.example', 'port': port}
            bodies = {
                'uri': ('vless://user@node.example:' + str(port)).encode(),
                'json': json.dumps({'proxies': [node]}).encode(),
                'yaml': ('proxies:\n  - type: ss\n    server: node.example\n'
                         '    port: ' + str(port) + '\n').encode(),
            }
            for encoding, body in bodies.items():
                with self.subTest(port=port, encoding=encoding):
                    self.assertEqual(discovery.valid_subscription(body), expected)


class AppendAtomicTests(unittest.TestCase):
    def test_preserves_history_and_appends_each_new_url_once_in_order(self):
        old = 'https://subscriptions.example/old.txt'
        first = 'https://subscriptions.example/first.txt'
        second = 'https://subscriptions.example/second.txt'
        history = '# 保留历史\n  ' + old + '  \n\n' + old
        for trailing_newline in ('', '\n'):
            with self.subTest(trailing_newline=repr(trailing_newline)):
                with tempfile.TemporaryDirectory() as directory:
                    output = Path(directory) / 'subscriptions.txt'
                    original = (history + trailing_newline).encode('utf-8')
                    output.write_bytes(original)
                    output.chmod(0o640)

                    added = discovery.append_atomic(output, [old, first, first, second, old])

                    self.assertEqual(added, 2)
                    self.assertEqual(output.read_bytes(),
                                     original + (b'' if trailing_newline else b'\n')
                                     + (first + '\n' + second + '\n').encode())
                    self.assertEqual(stat.S_IMODE(output.stat().st_mode), 0o640)

    def test_creates_nested_output_and_repeated_additions_are_idempotent(self):
        first = 'https://subscriptions.example/first.txt'
        second = 'https://subscriptions.example/second.txt'
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / 'nested' / 'subscriptions.txt'
            expected = (first + '\n' + second + '\n').encode()

            self.assertEqual(discovery.append_atomic(output, [first, second, first]), 2)
            self.assertEqual(output.read_bytes(), expected)
            self.assertEqual(discovery.append_atomic(output, [second, first, second]), 0)
            self.assertEqual(output.read_bytes(), expected)
            self.assertEqual(discovery.append_atomic(output, []), 0)
            self.assertEqual(output.read_bytes(), expected)

    def test_duplicate_only_append_preserves_history_without_final_newline(self):
        url = 'https://subscriptions.example/existing.txt'
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / 'subscriptions.txt'
            original = ('# existing history\n  ' + url + '  ').encode()
            output.write_bytes(original)

            self.assertEqual(discovery.append_atomic(output, [url, url]), 0)
            self.assertEqual(output.read_bytes(), original)


class CandidateUrlTests(unittest.TestCase):
    def test_rejects_credentials_in_authority_and_query(self):
        cases = [
            'https://user:password@subscriptions.example/public.txt',
            'https://user@subscriptions.example/public.txt',
            'https://:password@subscriptions.example/public.txt',
        ]
        for parameter in ('token', 'key', 'secret', 'password', 'auth', 'access', 'signature', 'TOKEN'):
            cases.append('https://subscriptions.example/public.txt?format=clash&'
                         + parameter + '=private-value')
        for url in cases:
            with self.subTest(url=url):
                self.assertIsNone(discovery.candidate_url(url))

    def test_rejects_readme_markdown_and_static_assets(self):
        cases = [
            'https://raw.githubusercontent.com/aiboboxx/v2rayfree/HEAD/README.md',
            'https://github.com/aiboboxx/v2rayfree/blob/main/README.md',
            'https://subscriptions.example/docs/guide.markdown',
            'https://raw.githubusercontent.com/free-nodes/v2rayfree/main/sub.png',
            'https://github.com/free-nodes/fanqiang/blob/main/assets/v2rayN.svg',
        ]
        for url in cases:
            with self.subTest(url=url):
                self.assertIsNone(discovery.candidate_url(url))

    def test_accepts_public_url_with_noncredential_query_and_github_sub_blob(self):
        url = 'https://subscriptions.example/public.txt?format=clash'
        self.assertEqual(discovery.candidate_url(url), url)
        self.assertEqual(
            discovery.candidate_url('https://github.com/free-nodes/v2rayfree/blob/main/sub'),
            'https://raw.githubusercontent.com/free-nodes/v2rayfree/main/sub',
        )


class DiscoverFilteringTests(unittest.TestCase):
    def test_discover_excludes_readme_self_and_extracts_real_subscription_link(self):
        readme_text = (
            '# 公益免费节点\n\n'
            '```\n'
            'vless://test-user@node.example:443?security=tls#Sample\n'
            '```\n\n'
            '- https://raw.githubusercontent.com/free-nodes/v2rayfree/main/sub\n'
            '![](https://raw.githubusercontent.com/free-nodes/v2rayfree/main/sub.png)\n'
        )
        readme_b64 = encoded(readme_text)

        def fake_github_json(path):
            if path.startswith('search/repositories'):
                return {'items': []}
            if path == 'repos/aiboboxx/v2rayfree/git/trees/HEAD?recursive=1':
                return {
                    'tree': [
                        {'type': 'blob', 'path': 'README.md', 'size': len(readme_text), 'sha': 'abc123'},
                    ],
                }
            if path == 'repos/aiboboxx/v2rayfree/git/blobs/abc123':
                return {'encoding': 'base64', 'content': readme_b64}
            raise AssertionError(f'unexpected github path: {path}')

        args = argparse.Namespace(
            no_seed=False,
            seed_repository='aiboboxx/v2rayfree',
            repositories=1,
            max_repositories=2,
            manifests=4,
            max_candidates=20,
        )
        report = {
            'unavailable_channels': [],
            'scan_warnings': 0,
            'repository_failures': 0,
        }
        original_github_json = discovery.github_json
        discovery.github_json = fake_github_json
        try:
            candidates = discovery.discover(args, report)
        finally:
            discovery.github_json = original_github_json

        self.assertNotIn('https://raw.githubusercontent.com/aiboboxx/v2rayfree/HEAD/README.md', candidates)
        self.assertNotIn('https://raw.githubusercontent.com/free-nodes/v2rayfree/main/sub.png', candidates)
        self.assertIn('https://raw.githubusercontent.com/free-nodes/v2rayfree/main/sub', candidates)
        self.assertIn(discovery.DEFAULT_PUBLIC_FEED, candidates)


class OpenSubLinkImportTests(unittest.TestCase):
    def _dummy_args(self, **overrides):
        defaults = {
            'opensublink_url': None,
            'auto_import': False,
            'no_auto_import': False,
            'import_group': None,
            'import_cron': None,
            'import_detect_profile_id': None,
            'pull_existing': False,
        }
        defaults.update(overrides)
        return argparse.Namespace(**defaults)

    def test_resolve_import_config_states(self):
        self.assertEqual(
            discovery.resolve_import_config(self._dummy_args(), env={}),
            {'enabled_feature': False, 'status': 'not_configured'},
        )
        missing_key = discovery.resolve_import_config(
            self._dummy_args(),
            env={'OPENSUBLINK_BASE_URL': 'http://127.0.0.1:8000'},
        )
        self.assertFalse(missing_key['enabled_feature'])
        self.assertEqual(missing_key['status'], 'incomplete_configuration')
        self.assertEqual(missing_key['reason'], 'missing_api_key')

        disabled = discovery.resolve_import_config(
            self._dummy_args(),
            env={
                'OPENSUBLINK_BASE_URL': 'http://127.0.0.1:8000',
                'OPENSUBLINK_API_KEY': 'sp_dummy_key',
                'OPENSUBLINK_AUTO_IMPORT': 'false',
            },
        )
        self.assertEqual(disabled, {'enabled_feature': False, 'status': 'disabled'})

        configured = discovery.resolve_import_config(
            self._dummy_args(),
            env={
                'SUBLINK_BASE_URL': 'http://127.0.0.1:8000/',
                'SUBLINK_API_KEY': 'sp_dummy_key',
                'OPENSUBLINK_IMPORT_GROUP': 'PublicFree',
                'OPENSUBLINK_IMPORT_CRON': '0 */8 * * *',
                'OPENSUBLINK_IMPORT_DETECT_PROFILE_ID': '2',
                'OPENSUBLINK_IMPORT_PULL_EXISTING': 'true',
            },
        )
        self.assertTrue(configured['enabled_feature'])
        self.assertEqual(configured['base_url'], 'http://127.0.0.1:8000')
        self.assertEqual(configured['group'], 'PublicFree')
        self.assertEqual(configured['cron_expr'], '0 */8 * * *')
        self.assertEqual(configured['detect_profile_id'], 2)
        self.assertTrue(configured['pull_existing'])

    def test_sync_opensublink_airports_skips_existing_and_imports_new_idempotently(self):
        existing_url = 'https://clashfree.cc/sub/clash.yaml'
        new_url = 'https://raw.githubusercontent.com/free-nodes/v2rayfree/main/sub'
        state = {
            'airports': [
                {'id': 7, 'name': 'Existing ClashFree', 'url': existing_url, 'enabled': True},
            ],
            'posts': [],
            'pulls': [],
        }

        def fake_request(base_url, api_key, method, path, payload=None, timeout=15):
            if method == 'GET' and path == '/api/v1/airports':
                return list(state['airports'])
            if method == 'POST' and path == '/api/v1/airports':
                state['posts'].append(payload)
                state['airports'].append({
                    'id': 8 + len(state['posts']),
                    'name': payload['name'],
                    'url': payload['url'],
                    'enabled': payload['enabled'],
                })
                return None
            if method == 'POST' and path.endswith('/pull'):
                state['pulls'].append(path)
                return None
            raise AssertionError(f'unexpected request: {method} {path}')

        cfg = {
            'base_url': 'http://127.0.0.1:8000',
            'api_key': 'sp_test_key',
            'group': 'PublicDiscovery',
            'cron_expr': '0 */6 * * *',
            'airport_enabled': True,
            'detect_profile_id': 1,
            'pull_existing': False,
            'timeout': 10,
        }
        batch = [
            (existing_url, 'clashfree.cc'),
            (new_url, 'aiboboxx/v2rayfree'),
            (new_url, 'aiboboxx/v2rayfree'),  # duplicate in same batch
        ]

        first = discovery.sync_opensublink_airports(batch, cfg, request_fn=fake_request)
        self.assertEqual(first['status'], 'ok')
        self.assertEqual(first['existing'], 1)
        self.assertEqual(first['skipped_existing'], 1)
        self.assertEqual(first['imported'], 1)
        self.assertEqual(first['pulled'], 1)
        self.assertEqual(first['failed'], 0)
        self.assertEqual(len(state['posts']), 1)
        created = state['posts'][0]
        self.assertEqual(created['url'], new_url)
        self.assertEqual(created['group'], 'PublicDiscovery')
        self.assertEqual(created['cronExpr'], '0 */6 * * *')
        self.assertTrue(created['enabled'])
        self.assertTrue(created['updateAfterDetect'])
        self.assertEqual(created['updateAfterDetectProfileId'], 1)
        self.assertTrue(created['updateAfterDetectChangedOnly'])

        # Second run with the same batch must be completely idempotent (0 new imports).
        second = discovery.sync_opensublink_airports(batch, cfg, request_fn=fake_request)
        self.assertEqual(second['status'], 'ok')
        self.assertEqual(second['existing'], 2)
        self.assertEqual(second['skipped_existing'], 2)
        self.assertEqual(second['imported'], 0)
        self.assertEqual(second['pulled'], 0)
        self.assertEqual(second['failed'], 0)
        self.assertEqual(len(state['posts']), 1)

        # With pull_existing=True, matched existing airports are pulled without duplicating.
        cfg_pull = dict(cfg, pull_existing=True)
        third = discovery.sync_opensublink_airports([(existing_url, 'clashfree.cc')], cfg_pull, request_fn=fake_request)
        self.assertEqual(third['skipped_existing'], 1)
        self.assertEqual(third['imported'], 0)
        self.assertEqual(third['pulled'], 1)
        self.assertEqual(state['pulls'], ['/api/v1/airports/7/pull'])

    def test_opensublink_api_request_checks_envelope_and_rejects_redirects(self):
        seen_headers = {}

        class Handler(BaseHTTPRequestHandler):
            def log_message(self, format, *args):
                return

            def do_GET(self):
                seen_headers['x-api-key'] = self.headers.get('X-API-Key')
                if self.path == '/api/v1/airports':
                    body = json.dumps({'code': 200, 'msg': 'ok', 'data': []}).encode('utf-8')
                    self.send_response(200)
                    self.send_header('Content-Type', 'application/json')
                    self.end_headers()
                    self.wfile.write(body)
                elif self.path == '/api/v1/fail-envelope':
                    body = json.dumps({'code': 500, 'msg': 'duplicate'}).encode('utf-8')
                    self.send_response(200)
                    self.send_header('Content-Type', 'application/json')
                    self.end_headers()
                    self.wfile.write(body)
                elif self.path == '/api/v1/redirect':
                    self.send_response(302)
                    self.send_header('Location', 'https://attacker.example/steal')
                    self.end_headers()

        server = HTTPServer(('127.0.0.1', 0), Handler)
        port = server.server_address[1]
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            base = f'http://127.0.0.1:{port}'
            data = discovery.opensublink_api_request(base, 'sp_local_key', 'GET', '/api/v1/airports')
            self.assertEqual(data, [])
            self.assertEqual(seen_headers['x-api-key'], 'sp_local_key')

            with self.assertRaises(discovery.OpenSubLinkImportError) as ctx:
                discovery.opensublink_api_request(base, 'sp_local_key', 'GET', '/api/v1/fail-envelope')
            self.assertEqual(str(ctx.exception), 'api_code_500')

            with self.assertRaises(discovery.OpenSubLinkImportError) as ctx:
                discovery.opensublink_api_request(base, 'sp_local_key', 'GET', '/api/v1/redirect')
            self.assertEqual(str(ctx.exception), 'unexpected_redirect')
        finally:
            server.shutdown()
            server.server_close()


if __name__ == '__main__':
    unittest.main()
