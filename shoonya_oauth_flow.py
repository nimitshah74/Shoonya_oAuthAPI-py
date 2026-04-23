from __future__ import annotations

import argparse
import json
import socket
import time
from dataclasses import dataclass
from datetime import datetime, timezone
from hashlib import sha256
from pathlib import Path
from typing import Any, Callable, Mapping, MutableMapping, Optional, Tuple
from urllib.parse import parse_qs, quote, urlencode, urlparse, urlunparse

import requests
import yaml
from requests.adapters import HTTPAdapter


DEFAULT_OAUTH_URL = "https://trade.shoonya.com/OAuthlogin/investor-entry-level/login"
DEFAULT_TOKEN_URL = "https://trade.shoonya.com/NorenWClientAPI/GenAcsTok"
DEFAULT_CREDENTIAL_PATH = Path(__file__).with_name("cred.yml")
LEGACY_OAUTH_URLS = {
    "https://api.shoonya.com/NorenWeb/authorize/oauth",
}
READ_ONLY_HEALTH_CHECKS = {
    "limits": "get_limits",
    "watchlist_names": "get_watch_list_names",
}

PLACEHOLDER_VALUES = {"", "none", "null", "your_auth_code_here"}
PLACEHOLDER_PREFIXES = ("your ", "replace ", "<")


class ShoonyaOAuthError(RuntimeError):
    """Raised when the Shoonya OAuth flow cannot safely continue."""


@dataclass(frozen=True)
class OAuthConfig:
    uid: str
    client_id: str
    secret_code: str
    oauth_url: str = DEFAULT_OAUTH_URL
    token_url: str = DEFAULT_TOKEN_URL
    oauth_query_param: str = "api_key"
    access_token: Optional[str] = None
    account_id: Optional[str] = None
    refresh_token: Optional[str] = None
    token_expires_in: Optional[str] = None
    password: Optional[str] = None
    totp_secret: Optional[str] = None
    pin: Optional[str] = None
    static_ip: Optional[str] = None
    http_proxy: Optional[str] = None
    https_proxy: Optional[str] = None
    proxy_host: Optional[str] = None
    proxy_port: Optional[str] = None
    proxy_userid: Optional[str] = None
    proxy_password: Optional[str] = None
    request_timeout: float = 20.0

    @classmethod
    def from_mapping(cls, values: Mapping[str, Any]) -> "OAuthConfig":
        uid = clean_value(first_present(values, "UID", "uid", "USERID", "user_id"))
        client_id = clean_value(
            first_present(values, "client_id", "Client_ID", "API_KEY", "api_key")
        )
        secret_code = clean_value(
            first_present(
                values,
                "Secret_Code",
                "SECRET_KEY",
                "secret_code",
                "secret_key",
            )
        )

        missing = []
        if uid is None:
            missing.append("UID")
        if client_id is None:
            missing.append("client_id")
        if secret_code is None:
            missing.append("Secret_Code")
        if missing:
            raise ShoonyaOAuthError(
                "Missing required OAuth config value(s): " + ", ".join(missing)
            )

        timeout = first_present(values, "request_timeout", "Request_Timeout")
        oauth_url = clean_value(first_present(values, "oauth_url", "OAuth_URL"))
        if oauth_url in LEGACY_OAUTH_URLS:
            oauth_url = None

        return cls(
            uid=uid,
            client_id=client_id,
            secret_code=secret_code,
            oauth_url=oauth_url or DEFAULT_OAUTH_URL,
            token_url=clean_value(first_present(values, "token_url", "Token_URL"))
            or DEFAULT_TOKEN_URL,
            oauth_query_param=clean_value(
                first_present(values, "oauth_query_param", "OAuth_Query_Param")
            )
            or "api_key",
            access_token=clean_value(
                first_present(values, "Access_token", "access_token")
            ),
            account_id=clean_value(first_present(values, "Account_ID", "actid")),
            refresh_token=clean_value(
                first_present(values, "Refresh_token", "refresh_token")
            ),
            token_expires_in=clean_value(
                first_present(values, "Token_expires_in", "expires_in")
            ),
            password=clean_value(first_present(values, "PASSWORD", "password")),
            totp_secret=clean_value(
                first_present(values, "TOTP_SECRET", "totp_secret", "TOTP", "totp")
            ),
            pin=clean_value(first_present(values, "PIN", "pin")),
            static_ip=clean_value(
                first_present(values, "Static_IP", "STATIC_IP", "static_ip", "source_ip")
            ),
            http_proxy=clean_value(
                first_present(values, "HTTP_PROXY", "http_proxy", "Http_Proxy")
            ),
            https_proxy=clean_value(
                first_present(values, "HTTPS_PROXY", "https_proxy", "Https_Proxy")
            ),
            proxy_host=clean_value(
                first_present(values, "Proxy_Host", "PROXY_HOST", "proxy_host")
            ),
            proxy_port=clean_value(
                first_present(values, "Proxy_Port", "PROXY_PORT", "proxy_port")
            ),
            proxy_userid=clean_value(
                first_present(
                    values,
                    "Proxy_UserID",
                    "PROXY_USERID",
                    "proxy_userid",
                    "Proxy_User",
                    "proxy_user",
                )
            ),
            proxy_password=clean_value(
                first_present(
                    values,
                    "Proxy_Password",
                    "PROXY_PASSWORD",
                    "proxy_password",
                    "Proxy_Pwd",
                    "proxy_pwd",
                )
            ),
            request_timeout=parse_timeout(timeout),
        )


@dataclass(frozen=True)
class TokenSet:
    access_token: str
    user_id: str
    account_id: str
    refresh_token: Optional[str] = None
    expires_in: Optional[str] = None
    susertoken: Optional[str] = None
    raw: Optional[Mapping[str, Any]] = None


def clean_value(value: Any) -> Optional[str]:
    if value is None:
        return None
    text = str(value).strip()
    if text.lower() in PLACEHOLDER_VALUES:
        return None
    if text.lower().startswith(PLACEHOLDER_PREFIXES):
        return None
    return text


def first_present(values: Mapping[str, Any], *keys: str) -> Any:
    lower_keys = {str(key).lower(): key for key in values}
    for key in keys:
        if key in values:
            return values[key]
        actual_key = lower_keys.get(key.lower())
        if actual_key is not None:
            return values[actual_key]
    return None


def parse_timeout(value: Any) -> float:
    if clean_value(value) is None:
        return 20.0
    try:
        timeout = float(value)
    except (TypeError, ValueError) as exc:
        raise ShoonyaOAuthError("request_timeout must be a positive number") from exc
    if timeout <= 0:
        raise ShoonyaOAuthError("request_timeout must be a positive number")
    return timeout


def load_credential_mapping(path: Path) -> MutableMapping[str, Any]:
    if not path.exists():
        raise ShoonyaOAuthError(f"Credential file not found: {path}")

    with path.open("r", encoding="utf-8") as handle:
        values = yaml.safe_load(handle) or {}

    if not isinstance(values, MutableMapping):
        raise ShoonyaOAuthError(f"Credential file must contain a YAML mapping: {path}")
    return values


def save_credential_mapping(path: Path, values: Mapping[str, Any]) -> None:
    with path.open("w", encoding="utf-8") as handle:
        yaml.safe_dump(dict(values), handle, sort_keys=False)


class SourceAddressAdapter(HTTPAdapter):
    def __init__(self, source_ip: str, **kwargs: Any):
        self.source_address = (source_ip, 0)
        super().__init__(**kwargs)

    def init_poolmanager(self, connections: int, maxsize: int, block: bool = False, **pool_kwargs: Any) -> None:
        pool_kwargs["source_address"] = self.source_address
        super().init_poolmanager(connections, maxsize, block=block, **pool_kwargs)

    def proxy_manager_for(self, proxy: str, **proxy_kwargs: Any) -> Any:
        proxy_kwargs["source_address"] = self.source_address
        return super().proxy_manager_for(proxy, **proxy_kwargs)


def validate_static_ip_is_local(static_ip: str) -> None:
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.bind((static_ip, 0))
    except OSError as exc:
        raise ShoonyaOAuthError(
            f"Static_IP {static_ip} is not assigned to this machine. "
            "Do not put the broker-whitelisted exit IP in Static_IP. "
            "Use Proxy_Host/Proxy_Port/Proxy_UserID/Proxy_Password for a "
            "static-IP proxy, or configure a VPN/interface that actually owns "
            "that IP."
        ) from exc


def build_network_session(config: OAuthConfig) -> requests.Session:
    session = requests.Session()
    proxies = {}
    proxy_url = build_proxy_url(config)
    if config.http_proxy is not None:
        proxies["http"] = config.http_proxy
    elif proxy_url is not None:
        proxies["http"] = proxy_url
    if config.https_proxy is not None:
        proxies["https"] = config.https_proxy
    elif proxy_url is not None:
        proxies["https"] = proxy_url
    if proxies:
        session.proxies.update(proxies)

    if config.static_ip is not None:
        validate_static_ip_is_local(config.static_ip)
        adapter = SourceAddressAdapter(config.static_ip)
        session.mount("http://", adapter)
        session.mount("https://", adapter)

    return session


def apply_network_config_to_api(config: OAuthConfig, api: Any) -> None:
    if (
        config.static_ip is None
        and config.http_proxy is None
        and config.https_proxy is None
        and config.proxy_host is None
    ):
        return

    session = build_network_session(config)
    try:
        import importlib

        noren_api_module = importlib.import_module("NorenRestApiPy.NorenApi")
    except ImportError as exc:
        raise ShoonyaOAuthError("Could not configure Shoonya API network route") from exc

    noren_api_module.requests = session
    setattr(api, "_shoonya_oauth_network_session", session)


def build_proxy_url(config: OAuthConfig) -> Optional[str]:
    if config.proxy_host is None:
        return None
    if config.proxy_port is None:
        raise ShoonyaOAuthError("Proxy_Port is required when Proxy_Host is configured")

    host = config.proxy_host
    if "://" in host:
        parsed = urlparse(host)
        scheme = parsed.scheme
        netloc = parsed.netloc
    else:
        scheme = "http"
        netloc = host

    credentials = ""
    if config.proxy_userid is not None:
        if config.proxy_password is None:
            raise ShoonyaOAuthError(
                "Proxy_Password is required when Proxy_UserID is configured"
            )
        credentials = (
            f"{quote(config.proxy_userid, safe='')}:"
            f"{quote(config.proxy_password, safe='')}@"
        )

    if ":" not in netloc.rsplit("@", 1)[-1]:
        netloc = f"{netloc}:{config.proxy_port}"
    return f"{scheme}://{credentials}{netloc}"


def build_oauth_url(config: OAuthConfig) -> str:
    parsed = urlparse(config.oauth_url)
    query = parse_qs(parsed.query, keep_blank_values=True)
    query[config.oauth_query_param] = [config.client_id]
    query.setdefault("route_to", [config.uid])
    return urlunparse(parsed._replace(query=urlencode(query, doseq=True)))


def _scan_performance_logs_for_code(driver: Any) -> Optional[str]:
    try:
        logs = driver.get_log("performance")
    except Exception:
        return None

    for entry in logs:
        try:
            message = json.loads(entry["message"])["message"]
        except (KeyError, TypeError, json.JSONDecodeError):
            continue

        if message.get("method") != "Network.requestWillBeSent":
            continue
        url = message.get("params", {}).get("request", {}).get("url", "")
        if "code=" not in url:
            continue
        try:
            return extract_auth_code(url)
        except ShoonyaOAuthError:
            continue
    return None


def _make_totp_value(secret_or_code: str) -> str:
    value = clean_value(secret_or_code)
    if value is None:
        raise ShoonyaOAuthError("TOTP_SECRET/TOTP cannot be empty")
    if value.isdigit() and len(value) == 6:
        return value

    try:
        import pyotp
    except ImportError as exc:  # pragma: no cover - pyotp is installed in tests
        raise ShoonyaOAuthError("pyotp is required for TOTP generation") from exc

    try:
        return pyotp.TOTP(value.replace(" ", "")).now()
    except Exception as exc:
        raise ShoonyaOAuthError("Unable to generate TOTP from TOTP_SECRET/TOTP") from exc


def _fast_fill(element: Any, value: str, pause: float = 0.1) -> None:
    element.click()
    time.sleep(pause)
    element.clear()
    element.send_keys(value)
    time.sleep(pause)


def fetch_auth_code_with_selenium(
    config: OAuthConfig,
    login_timeout: float = 90.0,
    headless: bool = True,
    driver_factory: Optional[Callable[[], Any]] = None,
) -> str:
    if config.password is None:
        raise ShoonyaOAuthError("Missing PASSWORD for automated OAuth login")
    if config.totp_secret is None and config.pin is None:
        raise ShoonyaOAuthError("Missing TOTP_SECRET/TOTP or PIN for automated OAuth login")

    try:
        from selenium import webdriver
        from selenium.webdriver.common.by import By
        from selenium.webdriver.support import expected_conditions as EC
        from selenium.webdriver.support.ui import WebDriverWait
    except ImportError as exc:  # pragma: no cover - dependency is installed in tests
        raise ShoonyaOAuthError("selenium is required for automated OAuth login") from exc

    if driver_factory is None:  # pragma: no cover - real browser launch is integration-only
        options = webdriver.ChromeOptions()
        if headless:
            options.add_argument("--headless=new")
        options.add_argument("--no-sandbox")
        options.add_argument("--disable-dev-shm-usage")
        options.add_argument("--window-size=1920,1080")
        chrome_proxy = config.https_proxy or config.http_proxy
        if chrome_proxy:
            options.add_argument(f"--proxy-server={chrome_proxy}")
        options.set_capability("goog:loggingPrefs", {"performance": "ALL"})
        driver = webdriver.Chrome(options=options)
    else:
        driver = driver_factory()

    try:
        wait = WebDriverWait(driver, int(login_timeout))
        driver.get(build_oauth_url(config))

        wait.until(EC.element_to_be_clickable((By.CSS_SELECTOR, "input[type='password']")))
        time.sleep(1)

        all_inputs = driver.find_elements(
            By.CSS_SELECTOR,
            "input:not([type='hidden']):not([type='checkbox']):not([type='radio'])",
        )
        visible_inputs = [element for element in all_inputs if element.is_displayed()]
        if len(visible_inputs) < 3:
            raise ShoonyaOAuthError(
                f"Expected at least 3 visible login inputs, found {len(visible_inputs)}"
            )

        _fast_fill(visible_inputs[0], config.uid)
        _fast_fill(visible_inputs[1], config.password)
        second_factor = _make_totp_value(config.totp_secret or config.pin or "")
        _fast_fill(visible_inputs[2], second_factor)

        login_button = wait.until(
            EC.element_to_be_clickable((By.XPATH, "//button[normalize-space()='LOGIN']"))
        )
        login_button.click()

        started_at = time.time()
        last_totp = second_factor
        while time.time() - started_at <= login_timeout:
            current_url = getattr(driver, "current_url", "")
            if "code=" in current_url:
                return extract_auth_code(current_url)

            code = _scan_performance_logs_for_code(driver)
            if code:
                return code

            if config.totp_secret is not None:  # pragma: no cover - timing-dependent retry guard
                new_totp = _make_totp_value(config.totp_secret)
                if new_totp != last_totp and time.time() - started_at > 45:
                    _fast_fill(visible_inputs[2], new_totp)
                    login_button.click()
                    last_totp = new_totp
                    started_at = time.time()
            time.sleep(0.5)

        raise ShoonyaOAuthError("Timed out waiting for OAuth redirect code")
    finally:
        try:
            driver.quit()
        except Exception:
            pass


def extract_auth_code(auth_code_or_url: str) -> str:
    value = clean_value(auth_code_or_url)
    if value is None:
        raise ShoonyaOAuthError("Authentication code cannot be empty")

    parsed = urlparse(value)
    if parsed.query or parsed.fragment:
        query_parts = [parsed.query, parsed.fragment]
        if "?" in parsed.fragment:
            query_parts.append(parsed.fragment.split("?", 1)[1])

        for query_part in query_parts:
            codes = parse_qs(query_part, keep_blank_values=True).get("code", [])
            for code in codes:
                clean_code = clean_value(code)
                if clean_code is not None:
                    return clean_code
        raise ShoonyaOAuthError(
            "Redirect URL does not contain a non-empty code parameter"
        )

    return value


def calculate_checksum(client_id: str, secret_code: str, auth_code: str) -> str:
    raw = f"{client_id}{secret_code}{auth_code}".encode("utf-8")
    return sha256(raw).hexdigest()


def exchange_code_for_token(
    config: OAuthConfig,
    auth_code_or_url: str,
    post: Optional[Callable[..., Any]] = None,
) -> TokenSet:
    code = extract_auth_code(auth_code_or_url)
    payload = {
        "code": code,
        "checksum": calculate_checksum(config.client_id, config.secret_code, code),
        "uid": config.uid,
    }
    request_body = "jData=" + json.dumps(payload, separators=(",", ":"))
    session = None if post is not None else build_network_session(config)
    post_fn = post or session.post

    try:
        response = post_fn(
            config.token_url,
            data=request_body,
            timeout=config.request_timeout,
        )
    except requests.RequestException as exc:
        raise ShoonyaOAuthError(f"Token exchange request failed: {exc}") from exc

    status_code = getattr(response, "status_code", 200)
    if status_code < 200 or status_code >= 300:
        raise ShoonyaOAuthError(f"Token exchange failed with HTTP {status_code}")

    body = getattr(response, "text", "")
    if not body:
        raise ShoonyaOAuthError("Token exchange returned an empty response")

    try:
        response_data = response.json()
    except (AttributeError, ValueError, json.JSONDecodeError):
        try:
            response_data = json.loads(body)
        except json.JSONDecodeError as exc:
            raise ShoonyaOAuthError("Token exchange returned invalid JSON") from exc

    if not isinstance(response_data, Mapping):
        raise ShoonyaOAuthError("Token exchange returned an unexpected JSON payload")

    stat = clean_value(response_data.get("stat"))
    if stat == "Not_Ok" or (stat is not None and stat != "Ok"):
        message = clean_value(response_data.get("emsg")) or json.dumps(response_data)
        if "INVALID_IP" in message:
            message = (
                f"{message}. Shoonya rejected this network IP. Whitelist the public "
                "IP shown by `python3 shoonya_oauth_flow.py --show-public-ip` in "
                "your Shoonya/API app settings, or run from an already whitelisted "
                "network/static IP."
            )
        raise ShoonyaOAuthError(f"Token exchange failed: {message}")

    access_token = clean_value(response_data.get("access_token"))
    if access_token is None:
        raise ShoonyaOAuthError("Token exchange response did not include access_token")

    user_id = (
        clean_value(response_data.get("USERID"))
        or clean_value(response_data.get("uid"))
        or config.uid
    )
    account_id = clean_value(response_data.get("actid")) or config.account_id or user_id
    if user_id is None or account_id is None:
        raise ShoonyaOAuthError("Token exchange response did not identify the account")

    return TokenSet(
        access_token=access_token,
        user_id=user_id,
        account_id=account_id,
        refresh_token=clean_value(response_data.get("refresh_token")),
        expires_in=clean_value(response_data.get("expires_in")),
        susertoken=clean_value(response_data.get("susertoken")),
        raw=response_data,
    )


def apply_token_to_api(api: Any, token: TokenSet) -> Mapping[str, str]:
    if not hasattr(api, "injectOAuthHeader"):
        raise ShoonyaOAuthError("API object does not support injectOAuthHeader")

    headers = api.injectOAuthHeader(token.access_token, token.user_id, token.account_id)
    if hasattr(api, "set_credentials"):
        api.set_credentials(token.access_token, token.user_id, token.account_id)
    return headers


def _default_api_factory() -> Any:
    from api_helper import NorenApiPy

    return NorenApiPy()


def run_health_check(api: Any, check: str = "limits") -> Any:
    method_name = READ_ONLY_HEALTH_CHECKS.get(check)
    if method_name is None:
        supported = ", ".join(sorted(READ_ONLY_HEALTH_CHECKS))
        raise ShoonyaOAuthError(f"Unsupported health check '{check}'. Use: {supported}")
    if not hasattr(api, method_name):
        raise ShoonyaOAuthError(f"API object does not support {method_name}")

    response = getattr(api, method_name)()
    if response is None:
        raise ShoonyaOAuthError(f"Health check '{check}' returned no response")
    if isinstance(response, Mapping):
        stat = clean_value(response.get("stat"))
        if stat == "Not_Ok" or (stat is not None and stat != "Ok"):
            message = clean_value(response.get("emsg")) or json.dumps(response)
            raise ShoonyaOAuthError(f"Health check '{check}' failed: {message}")
    return response


def get_public_ip(
    get: Optional[Callable[..., Any]] = None,
    timeout: float = 10.0,
    config: Optional[OAuthConfig] = None,
) -> str:
    session = None if get is not None else build_network_session(config) if config else None
    if get is not None:
        get_fn = get
    elif session is not None:
        get_fn = session.get
    else:
        get_fn = requests.get
    try:
        response = get_fn("https://api.ipify.org", timeout=timeout)
    except requests.RequestException as exc:
        raise ShoonyaOAuthError(f"Could not fetch public IP: {exc}") from exc

    status_code = getattr(response, "status_code", 200)
    if status_code < 200 or status_code >= 300:
        raise ShoonyaOAuthError(f"Could not fetch public IP: HTTP {status_code}")

    ip = clean_value(getattr(response, "text", ""))
    if ip is None:
        raise ShoonyaOAuthError("Could not fetch public IP: empty response")
    return ip


def get_authenticated_api(
    config_path: Path = DEFAULT_CREDENTIAL_PATH,
    auth_code: Optional[str] = None,
    api_factory: Optional[Callable[[], Any]] = None,
    post: Optional[Callable[..., Any]] = None,
    save_tokens: bool = True,
    auto_login: bool = False,
    headless: bool = True,
    input_fn: Callable[[str], str] = input,
    output_fn: Optional[Callable[[str], None]] = print,
) -> Any:
    config_path = Path(config_path).expanduser()
    values = load_credential_mapping(config_path)
    config = OAuthConfig.from_mapping(values)
    api = (api_factory or _default_api_factory)()
    apply_network_config_to_api(config, api)

    if config.access_token is not None:
        token = TokenSet(
            access_token=config.access_token,
            user_id=config.uid,
            account_id=config.account_id or config.uid,
            refresh_token=config.refresh_token,
            expires_in=config.token_expires_in,
        )
        apply_token_to_api(api, token)
        return api

    if auto_login and auth_code is None:
        if output_fn is not None:
            output_fn("Running automated Shoonya OAuth login in Selenium...")
        supplied_code = fetch_auth_code_with_selenium(config, headless=headless)
    else:
        if output_fn is not None:
            output_fn(
                "Automated login was not requested. Use --auto-login to fetch the "
                "OAuth code programmatically."
            )
        supplied_code = auth_code or input_fn("Paste auth code or full redirect URL: ")

    token = exchange_code_for_token(config, supplied_code, post=post)
    apply_token_to_api(api, token)

    if save_tokens:
        values["Access_token"] = token.access_token
        values["Account_ID"] = token.account_id
        values["Refresh_token"] = token.refresh_token
        values["Token_expires_in"] = token.expires_in
        values["Token_updated_at"] = datetime.now(timezone.utc).isoformat()
        save_credential_mapping(config_path, values)

    return api


def build_arg_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Authenticate Shoonya OAuth and prepare a NorenApiPy instance."
    )
    parser.add_argument(
        "--config",
        type=Path,
        default=DEFAULT_CREDENTIAL_PATH,
        help="Path to cred.yml.",
    )
    parser.add_argument(
        "--auth-code",
        help="Raw auth code from Shoonya redirect.",
    )
    parser.add_argument(
        "--redirect-url",
        help="Full redirect URL containing the code query parameter.",
    )
    parser.add_argument(
        "--print-login-url",
        action="store_true",
        help="Only print the OAuth login URL.",
    )
    parser.add_argument(
        "--show-public-ip",
        action="store_true",
        help="Print the public IP Shoonya is likely validating for API access.",
    )
    parser.add_argument(
        "--no-browser",
        action="store_true",
        help="Deprecated; browser opening is no longer used by this script.",
    )
    parser.add_argument(
        "--auto-login",
        action="store_true",
        help="Use headless Selenium to login and capture the OAuth code automatically.",
    )
    parser.add_argument(
        "--show-browser",
        action="store_true",
        help="Show Chrome during --auto-login instead of running headless.",
    )
    parser.add_argument(
        "--no-save",
        action="store_true",
        help="Do not write received tokens back to cred.yml.",
    )
    parser.add_argument(
        "--health-check",
        choices=sorted(READ_ONLY_HEALTH_CHECKS),
        help="After authentication, run a read-only API call to verify connectivity.",
    )
    return parser


def main(argv: Optional[Tuple[str, ...]] = None) -> int:  # pragma: no cover
    args = build_arg_parser().parse_args(argv)

    if args.print_login_url:
        config = OAuthConfig.from_mapping(load_credential_mapping(args.config))
        print(build_oauth_url(config))
        return 0
    if args.show_public_ip:
        config = OAuthConfig.from_mapping(load_credential_mapping(args.config))
        print(get_public_ip(config=config))
        return 0

    auth_code = args.auth_code or args.redirect_url
    api = get_authenticated_api(
        config_path=args.config,
        auth_code=auth_code,
        save_tokens=not args.no_save,
        auto_login=args.auto_login,
        headless=not args.show_browser,
    )
    if args.health_check:
        run_health_check(api, args.health_check)
        print(f"Read-only health check passed: {args.health_check}")
    print(
        "Shoonya API authenticated. Import get_authenticated_api() from "
        "shoonya_oauth_flow.py to receive the ready API instance."
    )
    return 0


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
