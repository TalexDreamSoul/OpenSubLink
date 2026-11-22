"""Offline regression tests: python3 -m unittest discover -s scripts -p 'test_public_subscription_discovery.py'."""

import base64
import json
from pathlib import Path
import stat
import tempfile
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
        ss = 'ss://' + encoded('aes-256-gcm:test-password@node.example:8388')
        ssr = 'ssr://' + encoded('node.example:8388:origin:aes-256-cfb:plain:cGFzcw')
        wrapped = encoded(uri + '\n' + ss).rstrip('=')
        cases = [
            ('plain_uri_list', ('# public nodes\ninvalid node\n' + uri + '\n' + ss).encode()),
            ('utf8_bom', ('\ufeff' + uri + '\n').encode('utf-8')),
            ('vmess_json_payload', vmess.encode()),
            ('shadowsocks_base64_payload', ss.encode()),
            ('shadowsocksr_base64_payload', ssr.encode()),
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

    def test_accepts_public_url_with_noncredential_query(self):
        url = 'https://subscriptions.example/public.txt?format=clash'
        self.assertEqual(discovery.candidate_url(url), url)


if __name__ == '__main__':
    unittest.main()
