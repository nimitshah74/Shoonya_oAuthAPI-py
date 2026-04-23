import hashlib
import json
import sys
import tempfile
import types
import unittest
from pathlib import Path
from unittest.mock import patch
from urllib.parse import parse_qs, urlparse

import requests
import yaml

from shoonya_oauth_flow import (
    DEFAULT_OAUTH_URL,
    DEFAULT_TOKEN_URL,
    OAuthConfig,
    ShoonyaOAuthError,
    SourceAddressAdapter,
    TokenSet,
    _default_api_factory,
    apply_network_config_to_api,
    apply_token_to_api,
    build_network_session,
    build_arg_parser,
    build_oauth_url,
    build_proxy_url,
    calculate_checksum,
    exchange_code_for_token,
    extract_auth_code,
    fetch_auth_code_with_selenium,
    get_public_ip,
    get_authenticated_api,
    load_credential_mapping,
    parse_timeout,
    run_health_check,
    validate_static_ip_is_local,
    _make_totp_value,
    _scan_performance_logs_for_code,
)


class FakeResponse:
    def __init__(self, payload=None, status_code=200, text=None, json_error=False):
        self.payload = payload
        self.status_code = status_code
        self.text = text if text is not None else json.dumps(payload)
        self.json_error = json_error

    def json(self):
        if self.json_error:
            raise ValueError("bad json")
        return self.payload


class FakeApi:
    def __init__(self):
        self.injected = []
        self.credentials = []

    def injectOAuthHeader(self, access_token, uid, account_id):
        self.injected.append((access_token, uid, account_id))
        return {"Authorization": f"Bearer {access_token}"}

    def set_credentials(self, access_token, uid, account_id):
        self.credentials.append((access_token, uid, account_id))

    def get_limits(self):
        return {"stat": "Ok", "request_time": "10:00:00 01-01-2026"}


class FakeElement:
    def __init__(self, displayed=True, enabled=True):
        self.displayed = displayed
        self.enabled = enabled
        self.values = []
        self.clicked = 0
        self.cleared = 0

    def is_displayed(self):
        return self.displayed

    def is_enabled(self):
        return self.enabled

    def click(self):
        self.clicked += 1

    def clear(self):
        self.cleared += 1

    def send_keys(self, value):
        self.values.append(value)


class FakeLoginDriver:
    def __init__(self, visible_input_count=3, redirect_url="https://cb.test/?code=ok"):
        self.inputs = [FakeElement() for _ in range(visible_input_count)]
        self.button = FakeElement()
        self.current_url = redirect_url
        self.redirect_url = redirect_url
        self.quit_called = False
        self.visited = []

    def get(self, url):
        self.visited.append(url)

    def find_element(self, by, selector):
        if selector == "input[type='password']":
            return self.inputs[1] if len(self.inputs) > 1 else FakeElement()
        return self.button

    def find_elements(self, by, selector):
        return self.inputs

    def get_log(self, log_type):
        return []

    def quit(self):
        self.quit_called = True



class ShoonyaOAuthFlowTest(unittest.TestCase):
    def test_config_accepts_aliases_defaults_and_placeholders(self):
        config = OAuthConfig.from_mapping(
            {
                "uid": "CLIENT1",
                "API_KEY": "client-123",
                "SECRET_KEY": "secret-456",
                "Access_token": "Your access token",
                "Account_ID": "Your account id",
                "request_timeout": "3.5",
            }
        )

        self.assertEqual(config.uid, "CLIENT1")
        self.assertEqual(config.client_id, "client-123")
        self.assertEqual(config.secret_code, "secret-456")
        self.assertEqual(config.oauth_url, DEFAULT_OAUTH_URL)
        self.assertEqual(config.token_url, DEFAULT_TOKEN_URL)
        self.assertIsNone(config.access_token)
        self.assertIsNone(config.account_id)
        self.assertEqual(config.request_timeout, 3.5)

    def test_config_accepts_static_ip_and_proxy_aliases(self):
        config = OAuthConfig.from_mapping(
            {
                "UID": "CLIENT1",
                "client_id": "ABC",
                "Secret_Code": "secret",
                "Static_IP": "10.0.0.5",
                "HTTP_PROXY": "http://proxy.test:8080",
                "HTTPS_PROXY": "http://secure-proxy.test:8080",
                "Proxy_Host": "proxy-host.test",
                "Proxy_Port": "443",
                "Proxy_UserID": "user",
                "Proxy_Password": "p@ss word",
            }
        )

        self.assertEqual(config.static_ip, "10.0.0.5")
        self.assertEqual(config.http_proxy, "http://proxy.test:8080")
        self.assertEqual(config.https_proxy, "http://secure-proxy.test:8080")
        self.assertEqual(config.proxy_host, "proxy-host.test")
        self.assertEqual(config.proxy_port, "443")
        self.assertEqual(config.proxy_userid, "user")
        self.assertEqual(config.proxy_password, "p@ss word")

    def test_build_proxy_url_from_parts(self):
        config = OAuthConfig(
            uid="CLIENT1",
            client_id="ABC",
            secret_code="secret",
            proxy_host="proxy-host.test",
            proxy_port="443",
            proxy_userid="user@example.com",
            proxy_password="p@ss word",
        )

        self.assertEqual(
            build_proxy_url(config),
            "http://user%40example.com:p%40ss%20word@proxy-host.test:443",
        )

        with_scheme = OAuthConfig(
            uid="CLIENT1",
            client_id="ABC",
            secret_code="secret",
            proxy_host="https://proxy-host.test",
            proxy_port="443",
        )
        self.assertEqual(build_proxy_url(with_scheme), "https://proxy-host.test:443")

    def test_build_proxy_url_rejects_incomplete_proxy(self):
        missing_port = OAuthConfig(
            uid="CLIENT1",
            client_id="ABC",
            secret_code="secret",
            proxy_host="proxy-host.test",
        )
        with self.assertRaisesRegex(ShoonyaOAuthError, "Proxy_Port"):
            build_proxy_url(missing_port)

        missing_password = OAuthConfig(
            uid="CLIENT1",
            client_id="ABC",
            secret_code="secret",
            proxy_host="proxy-host.test",
            proxy_port="443",
            proxy_userid="user",
        )
        with self.assertRaisesRegex(ShoonyaOAuthError, "Proxy_Password"):
            build_proxy_url(missing_password)

    def test_config_replaces_legacy_404_oauth_url(self):
        config = OAuthConfig.from_mapping(
            {
                "UID": "CLIENT1",
                "client_id": "ABC",
                "Secret_Code": "secret",
                "oauth_url": "https://api.shoonya.com/NorenWeb/authorize/oauth",
            }
        )

        self.assertEqual(config.oauth_url, DEFAULT_OAUTH_URL)

    def test_config_missing_required_values(self):
        with self.assertRaisesRegex(ShoonyaOAuthError, "UID, client_id"):
            OAuthConfig.from_mapping(
                {"UID": "Your account id", "Secret_Code": "secret"}
            )
        with self.assertRaisesRegex(ShoonyaOAuthError, "Secret_Code"):
            OAuthConfig.from_mapping({"UID": "CLIENT1", "client_id": "ABC"})

    def test_parse_timeout_rejects_bad_values(self):
        with self.assertRaisesRegex(ShoonyaOAuthError, "positive number"):
            parse_timeout("soon")
        with self.assertRaisesRegex(ShoonyaOAuthError, "positive number"):
            parse_timeout("0")

    def test_build_oauth_url_preserves_query_and_encodes_client(self):
        config = OAuthConfig.from_mapping(
            {
                "UID": "CLIENT1",
                "client_id": "id with space",
                "Secret_Code": "secret",
                "oauth_url": "https://example.test/login?foo=bar",
                "oauth_query_param": "api_key",
            }
        )

        parsed = urlparse(build_oauth_url(config))
        query = parse_qs(parsed.query)
        self.assertEqual(query["foo"], ["bar"])
        self.assertEqual(query["api_key"], ["id with space"])
        self.assertEqual(query["route_to"], ["CLIENT1"])

    def test_extract_auth_code_from_raw_query_and_fragment(self):
        self.assertEqual(extract_auth_code("raw-code"), "raw-code")
        self.assertEqual(
            extract_auth_code("https://redirect.test/cb?state=x&code=query-code"),
            "query-code",
        )
        self.assertEqual(
            extract_auth_code("https://redirect.test/cb#/done?code=fragment-code"),
            "fragment-code",
        )

    def test_extract_auth_code_rejects_missing_or_empty_code(self):
        with self.assertRaisesRegex(ShoonyaOAuthError, "cannot be empty"):
            extract_auth_code(" ")
        with self.assertRaisesRegex(ShoonyaOAuthError, "code parameter"):
            extract_auth_code("https://redirect.test/cb?code=&state=x")

    def test_calculate_checksum(self):
        expected = hashlib.sha256(b"ABC123x1y2z3").hexdigest()
        self.assertEqual(calculate_checksum("ABC", "123", "x1y2z3"), expected)

    def test_exchange_code_posts_doc_payload_and_uses_config_fallbacks(self):
        config = OAuthConfig.from_mapping(
            {
                "UID": "CLIENT1",
                "client_id": "ABC",
                "Secret_Code": "123",
                "Account_ID": "ACC1",
            }
        )
        calls = []

        def post(url, data, timeout):
            calls.append((url, data, timeout))
            return FakeResponse(
                {
                    "stat": "Ok",
                    "access_token": "access",
                    "refresh_token": "refresh",
                    "expires_in": "1756979040",
                }
            )

        token = exchange_code_for_token(config, "x1y2z3", post=post)

        self.assertEqual(token.access_token, "access")
        self.assertEqual(token.user_id, "CLIENT1")
        self.assertEqual(token.account_id, "ACC1")
        self.assertEqual(token.refresh_token, "refresh")
        self.assertEqual(calls[0][0], DEFAULT_TOKEN_URL)
        self.assertEqual(calls[0][2], 20.0)
        sent = json.loads(calls[0][1].removeprefix("jData="))
        self.assertEqual(sent["code"], "x1y2z3")
        self.assertEqual(sent["uid"], "CLIENT1")
        self.assertEqual(sent["checksum"], calculate_checksum("ABC", "123", "x1y2z3"))

    def test_exchange_code_prefers_response_user_and_account(self):
        config = OAuthConfig.from_mapping(
            {"UID": "CLIENT1", "client_id": "ABC", "Secret_Code": "123"}
        )

        token = exchange_code_for_token(
            config,
            "code",
            post=lambda *args, **kwargs: FakeResponse(
                {
                    "access_token": "access",
                    "USERID": "USER2",
                    "actid": "ACC2",
                    "susertoken": "session",
                }
            ),
        )

        self.assertEqual(token.user_id, "USER2")
        self.assertEqual(token.account_id, "ACC2")
        self.assertEqual(token.susertoken, "session")

    def test_exchange_code_rejects_failed_response(self):
        config = OAuthConfig.from_mapping(
            {"UID": "CLIENT1", "client_id": "ABC", "Secret_Code": "123"}
        )

        with self.assertRaisesRegex(ShoonyaOAuthError, "INVALID_VERIFIER"):
            exchange_code_for_token(
                config,
                "code",
                post=lambda *args, **kwargs: FakeResponse(
                    {"stat": "Not_Ok", "emsg": "INVALID_VERIFIER"}
                ),
            )

    def test_exchange_code_explains_invalid_ip(self):
        config = OAuthConfig.from_mapping(
            {"UID": "CLIENT1", "client_id": "ABC", "Secret_Code": "123"}
        )

        with self.assertRaisesRegex(ShoonyaOAuthError, "--show-public-ip"):
            exchange_code_for_token(
                config,
                "code",
                post=lambda *args, **kwargs: FakeResponse(
                    {"stat": "Not_Ok", "emsg": "Invalid Input : INVALID_IP"}
                ),
            )

    def test_exchange_code_rejects_http_error_empty_body_and_invalid_json(self):
        config = OAuthConfig.from_mapping(
            {"UID": "CLIENT1", "client_id": "ABC", "Secret_Code": "123"}
        )

        with self.assertRaisesRegex(ShoonyaOAuthError, "HTTP 500"):
            exchange_code_for_token(
                config,
                "code",
                post=lambda *args, **kwargs: FakeResponse({}, status_code=500),
            )
        with self.assertRaisesRegex(ShoonyaOAuthError, "empty response"):
            exchange_code_for_token(
                config,
                "code",
                post=lambda *args, **kwargs: FakeResponse({}, text=""),
            )
        with self.assertRaisesRegex(ShoonyaOAuthError, "invalid JSON"):
            exchange_code_for_token(
                config,
                "code",
                post=lambda *args, **kwargs: FakeResponse(
                    text="{bad", json_error=True
                ),
            )

    def test_exchange_code_rejects_missing_access_token_and_network_error(self):
        config = OAuthConfig.from_mapping(
            {"UID": "CLIENT1", "client_id": "ABC", "Secret_Code": "123"}
        )

        with self.assertRaisesRegex(ShoonyaOAuthError, "access_token"):
            exchange_code_for_token(
                config,
                "code",
                post=lambda *args, **kwargs: FakeResponse({"stat": "Ok"}),
            )

        def raising_post(*args, **kwargs):
            raise requests.Timeout("slow")

        with self.assertRaisesRegex(ShoonyaOAuthError, "request failed"):
            exchange_code_for_token(config, "code", post=raising_post)

    def test_exchange_code_rejects_unexpected_json_payload(self):
        config = OAuthConfig.from_mapping(
            {"UID": "CLIENT1", "client_id": "ABC", "Secret_Code": "123"}
        )

        with self.assertRaisesRegex(ShoonyaOAuthError, "unexpected JSON"):
            exchange_code_for_token(
                config,
                "code",
                post=lambda *args, **kwargs: FakeResponse(["not", "mapping"]),
            )

    def test_exchange_code_rejects_missing_account_identity(self):
        config = OAuthConfig(uid=None, client_id="ABC", secret_code="123")

        with self.assertRaisesRegex(ShoonyaOAuthError, "identify the account"):
            exchange_code_for_token(
                config,
                "code",
                post=lambda *args, **kwargs: FakeResponse({"access_token": "access"}),
            )

    def test_apply_token_to_api_injects_headers_and_websocket_credentials(self):
        api = FakeApi()
        headers = apply_token_to_api(api, TokenSet("access", "USER1", "ACC1"))

        self.assertEqual(headers, {"Authorization": "Bearer access"})
        self.assertEqual(api.injected, [("access", "USER1", "ACC1")])
        self.assertEqual(api.credentials, [("access", "USER1", "ACC1")])

    def test_apply_token_to_api_requires_inject_method(self):
        with self.assertRaisesRegex(ShoonyaOAuthError, "injectOAuthHeader"):
            apply_token_to_api(object(), TokenSet("access", "USER1", "ACC1"))

    def test_build_network_session_applies_proxy_and_source_ip(self):
        config = OAuthConfig(
            uid="CLIENT1",
            client_id="ABC",
            secret_code="secret",
            static_ip="10.0.0.5",
            http_proxy="http://proxy.test:8080",
            https_proxy="http://secure-proxy.test:8080",
        )

        with patch("shoonya_oauth_flow.validate_static_ip_is_local") as validate_ip:
            session = build_network_session(config)

        validate_ip.assert_called_once_with("10.0.0.5")
        self.assertEqual(session.proxies["http"], "http://proxy.test:8080")
        self.assertEqual(session.proxies["https"], "http://secure-proxy.test:8080")
        self.assertEqual(session.adapters["https://"].source_address, ("10.0.0.5", 0))

    def test_validate_static_ip_is_local_rejects_unassigned_ip(self):
        with patch("shoonya_oauth_flow.socket.socket") as socket_class:
            socket_class.return_value.__enter__.return_value.bind.side_effect = OSError(
                "nope"
            )

            with self.assertRaisesRegex(ShoonyaOAuthError, "not assigned"):
                validate_static_ip_is_local("157.20.241.1")

    def test_build_network_session_uses_proxy_parts(self):
        config = OAuthConfig(
            uid="CLIENT1",
            client_id="ABC",
            secret_code="secret",
            proxy_host="proxy-host.test",
            proxy_port="443",
            proxy_userid="user",
            proxy_password="pw",
        )

        session = build_network_session(config)

        self.assertEqual(session.proxies["http"], "http://user:pw@proxy-host.test:443")
        self.assertEqual(session.proxies["https"], "http://user:pw@proxy-host.test:443")

    def test_source_address_adapter_proxy_manager_keeps_source_ip(self):
        adapter = SourceAddressAdapter("10.0.0.5")
        manager = adapter.proxy_manager_for("http://proxy.test:8080")

        self.assertEqual(manager.connection_pool_kw["source_address"], ("10.0.0.5", 0))

    def test_apply_network_config_to_api_patches_noren_module(self):
        fake_module = types.ModuleType("NorenRestApiPy.NorenApi")
        original = sys.modules.get("NorenRestApiPy.NorenApi")
        sys.modules["NorenRestApiPy.NorenApi"] = fake_module
        api = FakeApi()
        config = OAuthConfig(
            uid="CLIENT1",
            client_id="ABC",
            secret_code="secret",
            https_proxy="http://secure-proxy.test:8080",
        )
        try:
            apply_network_config_to_api(config, api)
            self.assertIs(fake_module.requests, api._shoonya_oauth_network_session)
            self.assertEqual(
                fake_module.requests.proxies["https"],
                "http://secure-proxy.test:8080",
            )
        finally:
            if original is None:
                del sys.modules["NorenRestApiPy.NorenApi"]
            else:
                sys.modules["NorenRestApiPy.NorenApi"] = original

    def test_apply_network_config_to_api_noops_without_route(self):
        api = FakeApi()
        config = OAuthConfig(uid="CLIENT1", client_id="ABC", secret_code="secret")

        apply_network_config_to_api(config, api)

        self.assertFalse(hasattr(api, "_shoonya_oauth_network_session"))

    def test_apply_network_config_to_api_reports_import_error(self):
        api = FakeApi()
        config = OAuthConfig(
            uid="CLIENT1",
            client_id="ABC",
            secret_code="secret",
            static_ip="10.0.0.5",
        )

        with patch("shoonya_oauth_flow.validate_static_ip_is_local"):
            with patch("importlib.import_module", side_effect=ImportError):
                with self.assertRaisesRegex(ShoonyaOAuthError, "network route"):
                    apply_network_config_to_api(config, api)

    def test_get_authenticated_api_uses_existing_token_without_network(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "cred.yml"
            path.write_text(
                yaml.safe_dump(
                    {
                        "UID": "CLIENT1",
                        "client_id": "ABC",
                        "Secret_Code": "123",
                        "Access_token": "existing",
                        "Account_ID": "ACC1",
                    }
                ),
                encoding="utf-8",
            )

            def unexpected_post(*args, **kwargs):
                self.fail("token exchange should not be called")

            api = get_authenticated_api(
                config_path=path,
                api_factory=FakeApi,
                post=unexpected_post,
                output_fn=None,
            )

        self.assertEqual(api.injected, [("existing", "CLIENT1", "ACC1")])
        self.assertEqual(api.credentials, [("existing", "CLIENT1", "ACC1")])

    def test_get_authenticated_api_uses_uid_when_existing_token_has_no_account(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "cred.yml"
            path.write_text(
                yaml.safe_dump(
                    {
                        "UID": "CLIENT1",
                        "client_id": "ABC",
                        "Secret_Code": "123",
                        "Access_token": "existing",
                    }
                ),
                encoding="utf-8",
            )

            api = get_authenticated_api(
                config_path=path,
                api_factory=FakeApi,
                output_fn=None,
            )

        self.assertEqual(api.injected, [("existing", "CLIENT1", "CLIENT1")])

    def test_get_authenticated_api_exchanges_saves_and_returns_api(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "cred.yml"
            path.write_text(
                yaml.safe_dump(
                    {"UID": "CLIENT1", "client_id": "ABC", "Secret_Code": "123"}
                ),
                encoding="utf-8",
            )
            output = []

            api = get_authenticated_api(
                config_path=path,
                auth_code="https://redirect.test/cb?code=oauth-code",
                api_factory=FakeApi,
                post=lambda *args, **kwargs: FakeResponse(
                    {
                        "stat": "Ok",
                        "access_token": "new-token",
                        "actid": "ACC2",
                        "refresh_token": "refresh",
                        "expires_in": "tomorrow",
                    }
                ),
                output_fn=output.append,
            )
            saved = yaml.safe_load(path.read_text(encoding="utf-8"))

        self.assertEqual(api.injected, [("new-token", "CLIENT1", "ACC2")])
        self.assertIn("Automated login was not requested", output[0])
        self.assertEqual(saved["Access_token"], "new-token")
        self.assertEqual(saved["Account_ID"], "ACC2")
        self.assertEqual(saved["Refresh_token"], "refresh")
        self.assertEqual(saved["Token_expires_in"], "tomorrow")
        self.assertIn("Token_updated_at", saved)

    def test_get_authenticated_api_prompts_when_code_missing_and_can_skip_save(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "cred.yml"
            path.write_text(
                yaml.safe_dump(
                    {"UID": "CLIENT1", "client_id": "ABC", "Secret_Code": "123"}
                ),
                encoding="utf-8",
            )

            api = get_authenticated_api(
                config_path=path,
                api_factory=FakeApi,
                post=lambda *args, **kwargs: FakeResponse({"access_token": "token"}),
                save_tokens=False,
                input_fn=lambda prompt: "prompt-code",
                output_fn=None,
            )
            saved = yaml.safe_load(path.read_text(encoding="utf-8"))

        self.assertEqual(api.injected, [("token", "CLIENT1", "CLIENT1")])
        self.assertNotIn("Access_token", saved)

    def test_get_authenticated_api_can_auto_login(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "cred.yml"
            path.write_text(
                yaml.safe_dump(
                    {
                        "UID": "CLIENT1",
                        "client_id": "ABC",
                        "Secret_Code": "123",
                        "PASSWORD": "secret",
                        "TOTP": "123456",
                    }
                ),
                encoding="utf-8",
            )

            with patch(
                "shoonya_oauth_flow.fetch_auth_code_with_selenium",
                return_value="auto-code",
            ) as fetch_code:
                output = []
                get_authenticated_api(
                    config_path=path,
                    api_factory=FakeApi,
                    post=lambda *args, **kwargs: FakeResponse(
                        {"access_token": "token"}
                    ),
                    save_tokens=False,
                    auto_login=True,
                    output_fn=output.append,
                )

        fetch_code.assert_called_once()
        self.assertEqual(output, ["Running automated Shoonya OAuth login in Selenium..."])

    def test_scan_performance_logs_finds_code(self):
        class Driver:
            def get_log(self, log_type):
                return [
                    {"message": "{}"},
                    {
                        "message": json.dumps(
                            {
                                "message": {
                                    "method": "Network.responseReceived",
                                    "params": {},
                                }
                            }
                        )
                    },
                    {
                        "message": json.dumps(
                            {
                                "message": {
                                    "method": "Network.requestWillBeSent",
                                    "params": {"request": {"url": "https://example.test/cb"}},
                                }
                            }
                        )
                    },
                    {
                        "message": json.dumps(
                            {
                                "message": {
                                    "method": "Network.requestWillBeSent",
                                    "params": {
                                        "request": {
                                            "url": "https://example.test/cb?code="
                                        }
                                    },
                                }
                            }
                        )
                    },
                    {
                        "message": json.dumps(
                            {
                                "message": {
                                    "method": "Network.requestWillBeSent",
                                    "params": {
                                        "request": {
                                            "url": "https://example.test/cb?code=abc123"
                                        }
                                    },
                                }
                            }
                        )
                    },
                ]

        self.assertEqual(_scan_performance_logs_for_code(Driver()), "abc123")

    def test_scan_performance_logs_handles_failures(self):
        class Driver:
            def get_log(self, log_type):
                raise RuntimeError("no logs")

        self.assertIsNone(_scan_performance_logs_for_code(Driver()))

    def test_fetch_auth_code_with_selenium_captures_performance_log_code(self):
        class LogDriver(FakeLoginDriver):
            def __init__(self):
                super().__init__(redirect_url="")

            def get_log(self, log_type):
                return [
                    {
                        "message": json.dumps(
                            {
                                "message": {
                                    "method": "Network.requestWillBeSent",
                                    "params": {
                                        "request": {
                                            "url": "https://cb.test/?code=from-log"
                                        }
                                    },
                                }
                            }
                        )
                    }
                ]

        driver = LogDriver()
        config = OAuthConfig(
            uid="CLIENT1",
            client_id="ABC",
            secret_code="123",
            password="pw",
            pin="123456",
        )

        with patch("shoonya_oauth_flow.time.sleep", side_effect=lambda seconds: None):
            code = fetch_auth_code_with_selenium(config, driver_factory=lambda: driver)

        self.assertEqual(code, "from-log")

    def test_fetch_auth_code_with_selenium_ignores_quit_errors(self):
        class QuitErrorDriver(FakeLoginDriver):
            def quit(self):
                raise RuntimeError("quit failed")

        driver = QuitErrorDriver()
        config = OAuthConfig(
            uid="CLIENT1",
            client_id="ABC",
            secret_code="123",
            password="pw",
            pin="123456",
        )

        with patch("shoonya_oauth_flow.time.sleep", side_effect=lambda seconds: None):
            self.assertEqual(
                fetch_auth_code_with_selenium(config, driver_factory=lambda: driver),
                "ok",
            )

    def test_make_totp_value_accepts_static_code_and_rejects_empty(self):
        self.assertEqual(_make_totp_value("123456"), "123456")
        self.assertEqual(len(_make_totp_value("JBSWY3DPEHPK3PXP")), 6)
        with self.assertRaisesRegex(ShoonyaOAuthError, "cannot be empty"):
            _make_totp_value("")
        with self.assertRaisesRegex(ShoonyaOAuthError, "Unable to generate TOTP"):
            _make_totp_value("bad")

    def test_fetch_auth_code_requires_login_secrets(self):
        config = OAuthConfig(uid="CLIENT1", client_id="ABC", secret_code="123")

        with self.assertRaisesRegex(ShoonyaOAuthError, "PASSWORD"):
            fetch_auth_code_with_selenium(config)

        config = OAuthConfig(
            uid="CLIENT1",
            client_id="ABC",
            secret_code="123",
            password="pw",
        )
        with self.assertRaisesRegex(ShoonyaOAuthError, "TOTP_SECRET/TOTP or PIN"):
            fetch_auth_code_with_selenium(config)

    def test_fetch_auth_code_with_selenium_captures_current_url_code(self):
        driver = FakeLoginDriver()
        config = OAuthConfig(
            uid="CLIENT1",
            client_id="ABC",
            secret_code="123",
            password="pw",
            totp_secret="123456",
        )

        with patch("shoonya_oauth_flow.time.sleep", side_effect=lambda seconds: None):
            code = fetch_auth_code_with_selenium(
                config,
                driver_factory=lambda: driver,
            )

        self.assertEqual(code, "ok")
        self.assertTrue(driver.quit_called)
        self.assertEqual(driver.inputs[0].values, ["CLIENT1"])
        self.assertEqual(driver.inputs[1].values, ["pw"])
        self.assertEqual(driver.inputs[2].values, ["123456"])

    def test_fetch_auth_code_with_selenium_rejects_missing_visible_inputs(self):
        driver = FakeLoginDriver(visible_input_count=2)
        config = OAuthConfig(
            uid="CLIENT1",
            client_id="ABC",
            secret_code="123",
            password="pw",
            totp_secret="123456",
        )

        with patch("shoonya_oauth_flow.time.sleep", side_effect=lambda seconds: None):
            with self.assertRaisesRegex(ShoonyaOAuthError, "Expected at least 3"):
                fetch_auth_code_with_selenium(config, driver_factory=lambda: driver)

        self.assertTrue(driver.quit_called)

    def test_fetch_auth_code_with_selenium_times_out(self):
        driver = FakeLoginDriver(redirect_url="")
        config = OAuthConfig(
            uid="CLIENT1",
            client_id="ABC",
            secret_code="123",
            password="pw",
            pin="123456",
        )

        with patch("shoonya_oauth_flow.time.sleep", side_effect=lambda seconds: None):
            with self.assertRaisesRegex(ShoonyaOAuthError, "Timed out"):
                fetch_auth_code_with_selenium(
                    config,
                    login_timeout=0,
                    driver_factory=lambda: driver,
                )

        self.assertTrue(driver.quit_called)

    def test_default_api_factory_imports_lazy_helper(self):
        fake_module = types.ModuleType("api_helper")
        fake_module.NorenApiPy = FakeApi
        original = sys.modules.get("api_helper")
        sys.modules["api_helper"] = fake_module
        try:
            self.assertIsInstance(_default_api_factory(), FakeApi)
        finally:
            if original is None:
                del sys.modules["api_helper"]
            else:
                sys.modules["api_helper"] = original

    def test_run_health_check_calls_read_only_limits_endpoint(self):
        api = FakeApi()
        response = run_health_check(api)

        self.assertEqual(response["stat"], "Ok")

    def test_run_health_check_supports_watchlist_names_endpoint(self):
        class WatchlistApi:
            def get_watch_list_names(self):
                return {"stat": "Ok", "values": []}

        response = run_health_check(WatchlistApi(), "watchlist_names")

        self.assertEqual(response["values"], [])

    def test_run_health_check_rejects_unsupported_or_missing_method(self):
        with self.assertRaisesRegex(ShoonyaOAuthError, "Unsupported health check"):
            run_health_check(FakeApi(), "orders")
        with self.assertRaisesRegex(ShoonyaOAuthError, "does not support get_limits"):
            run_health_check(object())

    def test_run_health_check_rejects_none_and_not_ok_responses(self):
        class EmptyApi:
            def get_limits(self):
                return None

        class FailedApi:
            def get_limits(self):
                return {"stat": "Not_Ok", "emsg": "Session Expired"}

        with self.assertRaisesRegex(ShoonyaOAuthError, "returned no response"):
            run_health_check(EmptyApi())
        with self.assertRaisesRegex(ShoonyaOAuthError, "Session Expired"):
            run_health_check(FailedApi())

    def test_get_public_ip_success_and_failures(self):
        self.assertEqual(
            get_public_ip(get=lambda *args, **kwargs: FakeResponse(text="1.2.3.4")),
            "1.2.3.4",
        )

        with self.assertRaisesRegex(ShoonyaOAuthError, "HTTP 500"):
            get_public_ip(get=lambda *args, **kwargs: FakeResponse(text="", status_code=500))

        with self.assertRaisesRegex(ShoonyaOAuthError, "empty response"):
            get_public_ip(get=lambda *args, **kwargs: FakeResponse(text=""))

        def raising_get(*args, **kwargs):
            raise requests.Timeout("slow")

        with self.assertRaisesRegex(ShoonyaOAuthError, "Could not fetch public IP"):
            get_public_ip(get=raising_get)

    def test_get_public_ip_uses_configured_session_and_default_get(self):
        class Session:
            def get(self, url, timeout):
                return FakeResponse(text=f"{url}|{timeout}")

        config = OAuthConfig(uid="CLIENT1", client_id="ABC", secret_code="secret")

        with patch("shoonya_oauth_flow.build_network_session", return_value=Session()):
            self.assertEqual(
                get_public_ip(config=config, timeout=7),
                "https://api.ipify.org|7",
            )

        with patch("shoonya_oauth_flow.requests.get", return_value=FakeResponse(text="5.6.7.8")):
            self.assertEqual(get_public_ip(), "5.6.7.8")

    def test_load_credential_mapping_rejects_missing_or_non_mapping(self):
        with tempfile.TemporaryDirectory() as tmp:
            missing = Path(tmp) / "missing.yml"
            with self.assertRaisesRegex(ShoonyaOAuthError, "not found"):
                load_credential_mapping(missing)

            bad = Path(tmp) / "bad.yml"
            bad.write_text("- just\n- a\n- list\n", encoding="utf-8")
            with self.assertRaisesRegex(ShoonyaOAuthError, "YAML mapping"):
                load_credential_mapping(bad)

    def test_build_arg_parser(self):
        args = build_arg_parser().parse_args(
            ["--config", "custom.yml", "--auth-code", "code", "--no-save"]
        )

        self.assertEqual(args.config, Path("custom.yml"))
        self.assertEqual(args.auth_code, "code")
        self.assertTrue(args.no_save)

        health_args = build_arg_parser().parse_args(["--health-check", "limits"])
        self.assertEqual(health_args.health_check, "limits")

        auto_args = build_arg_parser().parse_args(["--auto-login", "--show-browser"])
        self.assertTrue(auto_args.auto_login)
        self.assertTrue(auto_args.show_browser)

        public_ip_args = build_arg_parser().parse_args(["--show-public-ip"])
        self.assertTrue(public_ip_args.show_public_ip)


if __name__ == "__main__":
    unittest.main()
