# SPDX-FileCopyrightText: GARDENA GmbH
#
# SPDX-License-Identifier: GPL-3.0-or-later

import dataclasses
import json
import logging
import re
from os import environ
from time import sleep

import pytest
import requests
import subprocess
from pathlib import Path

from requests import codes, Response


@dataclasses.dataclass
class ServerPorts:
    https_port: int
    http_port: int


NEW_SERVER_PORTS = ServerPorts(8888, 8080)

logging.basicConfig(level=logging.INFO)
logging.getLogger("urllib3").setLevel(logging.CRITICAL)

logger = logging.getLogger(__name__)

SCRIPT_DIR = Path(__file__).parent

# Must be longer than the service's own timeout for applying a Wi-Fi
# configuration, so the service times out first, not the client.
REQUEST_TIMEOUT_SECONDS = 90
# The default password is derived from the gateway ID used for development.
DEFAULT_PASSWORD = "7155a0b7"
assert len(DEFAULT_PASSWORD) == 8


class ConfigBackend:
    def __init__(self, directory, ports: ServerPorts):
        self.path = SCRIPT_DIR / directory / "bin"
        self.srv = None
        self.ports = ports
        self.session_key = None

    def _base_url_with_port(self, scheme="https"):
        port = self.ports.https_port if scheme == "https" else self.ports.http_port
        return f"{scheme}://localhost:{port}"

    def run_config_backend(self):
        server_executable = self.path / "gateway-config-backend"
        logging.info(f"Running {server_executable} in {self.path}")
        self.srv = subprocess.Popen(
            [server_executable],
            cwd=self.path,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        assert self.srv.pid != 0, "Failed to start the test server"
        sleep(1)

    def terminate(self):
        if self.srv:
            self.srv.terminate()
            self.srv.wait()

    def send_login_request(self, password):
        url = f"{self._base_url_with_port()}/login"
        return requests.post(
            url,
            json={"password": password},
            timeout=REQUEST_TIMEOUT_SECONDS,
            verify=False,
        )

    def login(self, password=DEFAULT_PASSWORD):
        resp = self.send_login_request(password)

        assert resp.status_code == codes.OK
        body = json.loads(resp.text)
        assert "session" in body
        session_key = body["session"]
        int(session_key, 16)  # Verify that session_key is a hex string
        self.session_key = session_key

    def set_custom_password(self, new_password, current_password) -> Response:
        resp = self.put(
            "password",
            json={"current_password": current_password, "password": new_password},
        )
        assert resp.status_code == codes.NO_CONTENT
        return resp

    def set_custom_password_and_login(self, new_password, old_password):
        resp = self.set_custom_password(new_password, old_password)
        assert resp.status_code == codes.NO_CONTENT
        self.post("logout")
        self.login(new_password)

    def delete_custom_password(self, current_password=DEFAULT_PASSWORD) -> Response:
        return self.delete("password", json={"current_password": current_password})

    def _add_session_key_to_headers(self, **kwargs):
        if self.session_key:
            headers = {"X-session": self.session_key}
            if "headers" in kwargs:
                kwargs["headers"].update(headers)
            else:
                kwargs["headers"] = headers
        return kwargs

    def _request(self, method, endpoint, scheme="https", **kwargs):
        url = f"{self._base_url_with_port(scheme)}/{endpoint}"
        # Applying a Wi-Fi configuration can take a while and answers with 408 on
        # its own. The client timeout must be longer, or a slow response looks
        # like a client error instead of a failure of the service under test.
        request_timeout = kwargs.pop("timeout", REQUEST_TIMEOUT_SECONDS)
        logger.info(
            f"Sending {method} request to {url} with headers {kwargs.get('headers')}"
        )
        return requests.request(
            method,
            url,
            **self._add_session_key_to_headers(**kwargs),
            timeout=request_timeout,
            verify=False,
        )

    def get(self, endpoint, **kwargs):
        return self._request("GET", endpoint, **kwargs)

    def post(self, endpoint, **kwargs):
        return self._request("POST", endpoint, **kwargs)

    def put(self, endpoint, **kwargs):
        return self._request("PUT", endpoint, **kwargs)

    def delete(self, endpoint, **kwargs):
        return self._request("DELETE", endpoint, **kwargs)


@pytest.fixture(scope="function")
def config_backend(tmp_path):
    # each test gets its own password file, so no custom password survives a test
    environ["TEST_PASSWORD_FILE"] = str(tmp_path / "password")
    srv = ConfigBackend("test-server", NEW_SERVER_PORTS)
    srv.run_config_backend()
    yield srv
    srv.terminate()


@pytest.fixture(scope="function")
def config_backend_logged_in(config_backend):
    config_backend.login()
    yield config_backend
    resp = config_backend.post("logout")
    assert resp.status_code == codes.NO_CONTENT


def test_redirect_http_to_https(config_backend):
    srv = config_backend
    resp = srv.get("simple.html", scheme="http", allow_redirects=False)
    assert resp.status_code == codes.MOVED_PERMANENTLY
    location = resp.headers["Location"]
    assert re.match("https://localhost:[0-9]{4}/simple.html", location)


def assert_body_field(body_json, field_name, expected_regex):
    assert field_name in body_json, (
        f"'{field_name}' not in keys '{list(body_json.keys())}' of body"
    )
    assert re.match(expected_regex, body_json[field_name]), (
        f"Value '{body_json[field_name]}' of field '{field_name}' does not match '{expected_regex}'"
    )


def test_version_endpoint(config_backend):
    resp = config_backend.get("version")
    assert resp.status_code == codes.OK
    body = json.loads(resp.text)
    assert_body_field(body, "gateway_version", "^[0-9.]+$")


def test_login(config_backend_logged_in):
    assert re.match("^[A-Za-z0-9]+$", config_backend_logged_in.session_key), (
        f"Session is not a hex string: {config_backend_logged_in.session_key}"
    )


def test_logout(config_backend):
    config_backend.login()
    resp = config_backend.get("timezone")
    assert resp.status_code == codes.OK
    resp = config_backend.post("logout")
    assert resp.status_code == codes.NO_CONTENT
    resp = config_backend.get("timezone")
    assert resp.status_code == codes.UNAUTHORIZED


def test_get_timezone(config_backend_logged_in):
    resp = config_backend_logged_in.get("timezone")
    assert resp.status_code == codes.OK
    body = resp.text
    assert '"Europe/Zurich"' in body


def test_get_timezone_list(config_backend_logged_in):
    resp = config_backend_logged_in.get("timezone_list")
    assert resp.status_code == codes.OK
    body = resp.text
    # Check if the response contains a long list of timezones. The length is chosen arbitrarily.
    assert len(resp.text) > 1000, "Expecting a long list of timezones"
    assert '"Europe/Zurich"' in body


def test_get_ap(config_backend_logged_in):
    resp = config_backend_logged_in.get("ap")
    assert resp.status_code == codes.OK
    body = json.loads(resp.text)
    assert "active" in body
    assert body["active"] is False


def test_get_simple(config_backend):
    resp = config_backend.get("simple.html")
    assert resp.status_code == codes.OK
    body = resp.text
    assert "<!doctype html>" in body
    assert "<title>GARDENA smart Gateway</title>" in body


def test_put_too_long_ssid(config_backend_logged_in):
    """An SSID longer than 32 characters is rejected without attempting to connect."""
    ssid = "012345678901234567890123456789012"
    assert len(ssid) == 33
    config = {"ssid": ssid, "key_mgmt": "WPA-PSK", "psk": "some-pw"}
    resp = config_backend_logged_in.put(
        "wifi", data=json.dumps(config), headers={"Content-Type": "application/json"}
    )
    assert resp.status_code == codes.BAD_REQUEST


def test_put_empty_ssid(config_backend_logged_in):
    """An empty SSID is rejected without attempting to connect."""
    config = {"ssid": "", "key_mgmt": "WPA-PSK", "psk": "supersecret"}
    resp = config_backend_logged_in.put(
        "wifi", data=json.dumps(config), headers={"Content-Type": "application/json"}
    )
    assert resp.status_code == codes.BAD_REQUEST


def test_put_missing_psk(config_backend_logged_in):
    """An encrypted network without a key is rejected without attempting to connect."""
    config = {"ssid": "some-ssid", "key_mgmt": "WPA-PSK", "psk": ""}
    resp = config_backend_logged_in.put(
        "wifi", data=json.dumps(config), headers={"Content-Type": "application/json"}
    )
    assert resp.status_code == codes.BAD_REQUEST


def test_set_custom_password(config_backend_logged_in):
    config_backend = config_backend_logged_in

    # set custom password
    resp = config_backend.set_custom_password("some-password", DEFAULT_PASSWORD)
    assert resp.status_code == codes.NO_CONTENT
    config_backend.post("logout")
    # try to log in with the original password
    resp = config_backend.send_login_request(DEFAULT_PASSWORD)
    assert resp.status_code == codes.UNAUTHORIZED

    # set another custom password
    config_backend.login("some-password")
    resp = config_backend.set_custom_password("some-other-password", "some-password")
    assert resp.status_code == codes.NO_CONTENT
    config_backend.post("logout")
    # try to log in with the first custom password
    resp = config_backend.send_login_request("some-password")
    assert resp.status_code == codes.UNAUTHORIZED
    # try to log in with the original password
    resp = config_backend.send_login_request(DEFAULT_PASSWORD)
    assert resp.status_code == codes.UNAUTHORIZED


def test_set_custom_password_invalidates_existing_session(config_backend_logged_in):
    config_backend = config_backend_logged_in

    resp = config_backend.set_custom_password("some-password", DEFAULT_PASSWORD)
    assert resp.status_code == codes.NO_CONTENT

    # the session used to set the password must not still be valid
    resp = config_backend.get("timezone")
    assert resp.status_code == codes.UNAUTHORIZED


def test_delete_custom_password_invalidates_existing_session(config_backend_logged_in):
    config_backend = config_backend_logged_in
    config_backend.set_custom_password_and_login("some-password", DEFAULT_PASSWORD)

    resp = config_backend.delete_custom_password("some-password")
    assert resp.status_code == codes.NO_CONTENT

    # the session used to delete the custom password must not still be valid
    resp = config_backend.get("timezone")
    assert resp.status_code == codes.UNAUTHORIZED


def test_delete_custom_password(config_backend_logged_in):
    config_backend = config_backend_logged_in
    # set custom password
    resp = config_backend.set_custom_password("some-password", DEFAULT_PASSWORD)
    assert resp.status_code == codes.NO_CONTENT
    # ensure that we can log in with the custom password
    config_backend.post("logout")
    config_backend.login("some-password")
    # delete custom password
    resp = config_backend.delete_custom_password("some-password")
    assert resp.status_code == codes.NO_CONTENT
    # log out and try to log in with the custom password
    config_backend.post("logout")
    resp = config_backend.send_login_request("some-password")
    assert resp.status_code == codes.UNAUTHORIZED
    # log in with the default password
    resp = config_backend.send_login_request(DEFAULT_PASSWORD)
    assert resp.status_code == codes.OK


def test_delete_default_password(config_backend_logged_in):
    resp = config_backend_logged_in.delete_custom_password()
    assert resp.status_code == codes.BAD_REQUEST


def test_set_custom_password_only_authorized(config_backend):
    new_password = "my-new-password"
    resp = config_backend.put(
        "password",
        json={
            "current_password": DEFAULT_PASSWORD,
            "password": new_password,
        },
    )
    assert resp.status_code == codes.UNAUTHORIZED


def test_delete_custom_password_only_authorized(config_backend):
    resp = config_backend.delete_custom_password()
    assert resp.status_code == codes.UNAUTHORIZED


def test_set_custom_password_too_long(config_backend_logged_in):
    config_backend = config_backend_logged_in
    new_password = "a" * 51
    resp = config_backend.put(
        "password",
        json={
            "current_password": DEFAULT_PASSWORD,
            "password": new_password,
        },
    )
    assert resp.status_code == codes.BAD_REQUEST
    assert resp.text == ""


def test_set_custom_password_too_short(config_backend_logged_in):
    config_backend = config_backend_logged_in
    new_password = "a" * 7
    resp = config_backend.put(
        "password",
        json={
            "current_password": DEFAULT_PASSWORD,
            "password": new_password,
        },
    )
    assert resp.status_code == codes.BAD_REQUEST
    assert resp.text == ""


def test_set_custom_password_wrong_current_password(config_backend_logged_in):
    resp = config_backend_logged_in.put(
        "password",
        json={"current_password": "not-the-password", "password": "my-new-password"},
    )
    assert resp.status_code == codes.FORBIDDEN


def test_delete_custom_password_wrong_current_password(config_backend_logged_in):
    config_backend = config_backend_logged_in
    config_backend.set_custom_password("some-password", DEFAULT_PASSWORD)
    config_backend.login("some-password")

    resp = config_backend.delete_custom_password("not-the-password")
    assert resp.status_code == codes.FORBIDDEN

    # the custom password is still in place
    config_backend.post("logout")
    resp = config_backend.send_login_request("some-password")
    assert resp.status_code == codes.OK


def test_set_custom_password_without_current_password(config_backend_logged_in):
    resp = config_backend_logged_in.put(
        "password", json={"password": "my-new-password"}
    )
    assert resp.status_code == codes.UNPROCESSABLE_ENTITY


def test_delete_custom_password_without_current_password(config_backend_logged_in):
    resp = config_backend_logged_in.delete("password", json={})
    assert resp.status_code == codes.UNPROCESSABLE_ENTITY


# This is the last test, as it triggers the rate limiter and may affect other tests.
def test_rate_limiter(config_backend):
    pwd = "wrong-password"
    for _ in range(20):
        resp = config_backend.send_login_request(pwd)
        assert resp.status_code == codes.UNAUTHORIZED
    resp = config_backend.send_login_request(pwd)
    assert resp.status_code == codes.TOO_MANY_REQUESTS
