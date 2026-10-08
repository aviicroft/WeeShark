"""
Unit and Integration Tests for WebGuard Scanner Engine (scanner.py)
"""

import pytest
import sys
import os

# Add webguard directory to module lookup path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..', 'webguard')))

from scanner import (
    is_private_or_restricted_ip,
    validate_url,
    check_https,
    check_headers,
    parse_raw_cookie_attributes,
    check_cookies,
    check_server_info,
    probe_single_port,
    check_ports,
    calculate_score,
    generate_recommendations,
    SafeRedirectHandler
)


class TestSSRFProtection:
    def test_loopback_ips_blocked(self):
        assert is_private_or_restricted_ip('127.0.0.1') is True
        assert is_private_or_restricted_ip('127.0.0.2') is True
        assert is_private_or_restricted_ip('::1') is True

    def test_private_subnets_blocked(self):
        assert is_private_or_restricted_ip('10.0.0.1') is True
        assert is_private_or_restricted_ip('10.255.255.255') is True
        assert is_private_or_restricted_ip('172.16.0.1') is True
        assert is_private_or_restricted_ip('172.31.255.255') is True
        assert is_private_or_restricted_ip('192.168.0.1') is True
        assert is_private_or_restricted_ip('192.168.1.254') is True

    def test_cloud_metadata_link_local_blocked(self):
        assert is_private_or_restricted_ip('169.254.169.254') is True
        assert is_private_or_restricted_ip('169.254.1.1') is True

    def test_public_ips_allowed(self):
        assert is_private_or_restricted_ip('8.8.8.8') is False
        assert is_private_or_restricted_ip('1.1.1.1') is False
        assert is_private_or_restricted_ip('93.184.216.34') is False

    def test_invalid_ip_treated_as_restricted(self):
        assert is_private_or_restricted_ip('not-an-ip') is True


class TestURLValidation:
    def test_empty_or_invalid_type_raises_error(self):
        with pytest.raises(ValueError, match='Please provide a valid website URL'):
            validate_url('')
        with pytest.raises(ValueError, match='Please provide a valid website URL'):
            validate_url(None)

    def test_missing_scheme_defaults_to_https(self):
        url, host, ip = validate_url('example.com')
        assert url.startswith('https://example.com')
        assert host == 'example.com'
        assert ip is not None

    def test_invalid_protocol_rejected(self):
        with pytest.raises(ValueError, match='Only HTTP and HTTPS are permitted'):
            validate_url('ftp://example.com')
        with pytest.raises(ValueError, match='Only HTTP and HTTPS are permitted'):
            validate_url('file:///etc/passwd')

    def test_localhost_and_internal_hostnames_blocked(self):
        with pytest.raises(ValueError, match='SSRF Protection'):
            validate_url('http://localhost')
        with pytest.raises(ValueError, match='SSRF Protection'):
            validate_url('http://127.0.0.1')
        with pytest.raises(ValueError, match='SSRF Protection'):
            validate_url('http://app.internal')
        with pytest.raises(ValueError, match='SSRF Protection'):
            validate_url('http://service.local')
        with pytest.raises(ValueError, match='SSRF Protection'):
            validate_url('http://metadata.google.internal')


class TestSafeRedirectHandler:
    def test_redirect_to_internal_ip_blocked(self):
        handler = SafeRedirectHandler()
        with pytest.raises(ValueError, match='SSRF Protection'):
            handler.redirect_request(None, None, 302, 'Found', {}, 'http://127.0.0.1/admin')

    def test_redirect_to_metadata_blocked(self):
        handler = SafeRedirectHandler()
        with pytest.raises(ValueError, match='SSRF Protection'):
            handler.redirect_request(None, None, 301, 'Moved', {}, 'http://169.254.169.254/latest')


class TestSecurityHeadersCheck:
    def test_all_headers_present(self):
        headers = {
            'Content-Security-Policy': "default-src 'self'",
            'X-Frame-Options': 'DENY',
            'X-Content-Type-Options': 'nosniff',
            'Strict-Transport-Security': 'max-age=31536000; includeSubDomains'
        }
        res = check_headers(headers)
        assert len(res) == 4
        assert all(h['rating'] == 'PASS' for h in res)
        assert all(h['status'] == 'Present' for h in res)

    def test_missing_headers_flagged(self):
        res = check_headers({})
        assert len(res) == 4
        assert all(h['rating'] == 'WARNING' for h in res)
        assert all(h['status'] == 'Missing' for h in res)


class TestCookieSecurityCheck:
    def test_no_cookies_returns_pass(self):
        res = check_cookies([])
        assert res['has_cookies'] is False
        assert res['status'] == 'PASS'
        assert res['count'] == 0

    def test_cookie_attribute_extraction(self):
        raw = 'sessionid=xyz123; Secure; HttpOnly; SameSite=Strict; Path=/'
        attrs = parse_raw_cookie_attributes(raw)
        assert attrs['name'] == 'sessionid'
        assert attrs['secure'] is True
        assert attrs['httponly'] is True
        assert attrs['samesite'] == 'Strict'

    def test_cookie_case_insensitivity(self):
        raw = 'token=abc; secure; httponly; samesite=none'
        attrs = parse_raw_cookie_attributes(raw)
        assert attrs['secure'] is True
        assert attrs['httponly'] is True
        assert attrs['samesite'] == 'None'

    def test_insecure_cookies_flagged(self):
        raw_list = ['user=john; Path=/']
        res = check_cookies(raw_list)
        assert res['has_cookies'] is True
        assert res['status'] == 'WARNING'
        assert 'Secure' in res['message']
        assert 'HttpOnly' in res['message']


class TestServerDisclosureCheck:
    def test_hidden_server_passes(self):
        res = check_server_info({})
        assert res['status'] == 'PASS'
        assert res['server'] == 'Hidden / Not Disclosed'

    def test_version_leak_triggers_warning(self):
        res = check_server_info({'Server': 'Apache/2.4.41 (Ubuntu)'})
        assert res['status'] == 'WARNING'
        assert 'Apache/2.4.41' in res['server']
        assert 'version numbers' in res['message']

    def test_generic_tokens_pass(self):
        res = check_server_info({'Server': 'cloudflare'})
        assert res['status'] == 'PASS'


class TestPortCheck:
    def test_single_port_returns_expected_format(self):
        port, status = probe_single_port('127.0.0.1', 65530)
        assert port == 65530
        assert status in ('Open', 'Closed')

    def test_check_ports_returns_five_standard_ports(self):
        results = check_ports('127.0.0.1')
        assert len(results) == 5
        ports = [r['port'] for r in results]
        assert ports == [80, 443, 22, 21, 8080]


class TestScoringAndRecommendations:
    def test_high_security_scoring(self):
        https_res = {'status': 'PASS', 'score_points': 25, 'message': 'OK'}
        headers_res = [
            {'header': 'Content-Security-Policy', 'status': 'Present', 'rating': 'PASS'},
            {'header': 'Strict-Transport-Security', 'status': 'Present', 'rating': 'PASS'},
            {'header': 'X-Frame-Options', 'status': 'Present', 'rating': 'PASS'},
            {'header': 'X-Content-Type-Options', 'status': 'Present', 'rating': 'PASS'},
        ]
        cookies_res = {'has_cookies': False, 'status': 'PASS'}
        server_res = {'status': 'PASS', 'server': 'Hidden'}
        ports_res = [
            {'port': 80, 'status': 'Open', 'is_risk': False},
            {'port': 443, 'status': 'Open', 'is_risk': False},
            {'port': 22, 'status': 'Closed', 'is_risk': False},
            {'port': 21, 'status': 'Closed', 'is_risk': False},
            {'port': 8080, 'status': 'Closed', 'is_risk': False},
        ]
        score, risk_level, badge_color = calculate_score(
            https_res, headers_res, cookies_res, server_res, ports_res
        )
        assert score == 100
        assert risk_level == 'EXCELLENT'
        assert badge_color == 'emerald'

    def test_insecure_target_scoring(self):
        https_res = {'status': 'FAIL', 'score_points': 0, 'message': 'Plaintext'}
        headers_res = [
            {'header': 'Content-Security-Policy', 'status': 'Missing', 'rating': 'WARNING'},
            {'header': 'Strict-Transport-Security', 'status': 'Missing', 'rating': 'WARNING'},
            {'header': 'X-Frame-Options', 'status': 'Missing', 'rating': 'WARNING'},
            {'header': 'X-Content-Type-Options', 'status': 'Missing', 'rating': 'WARNING'},
        ]
        cookies_res = {
            'has_cookies': True,
            'status': 'WARNING',
            'cookies': [{'name': 'c1', 'secure': False, 'httponly': False, 'samesite': 'None'}]
        }
        server_res = {'status': 'WARNING', 'server': 'Apache/2.2.8', 'exposed_details': 'Apache/2.2.8'}
        ports_res = [
            {'port': 80, 'status': 'Open', 'is_risk': False},
            {'port': 443, 'status': 'Closed', 'is_risk': False},
            {'port': 22, 'status': 'Open', 'is_risk': True, 'service': 'SSH'},
            {'port': 21, 'status': 'Open', 'is_risk': True, 'service': 'FTP'},
            {'port': 8080, 'status': 'Open', 'is_risk': True, 'service': 'Proxy'},
        ]
        score, risk_level, badge_color = calculate_score(
            https_res, headers_res, cookies_res, server_res, ports_res
        )
        assert score < 50
        assert risk_level == 'CRITICAL'
        assert badge_color == 'rose'

        recs = generate_recommendations(
            https_res, headers_res, cookies_res, server_res, ports_res
        )
        assert len(recs) >= 4
        categories = [r['category'] for r in recs]
        assert 'Encryption & Transport' in categories
        assert 'HTTP Security Headers' in categories
        assert 'Port Exposure' in categories

