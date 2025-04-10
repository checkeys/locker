# coding:utf-8

from http.server import ThreadingHTTPServer
import os
from typing import MutableMapping
from typing import Optional
from typing import Tuple
from urllib.parse import parse_qs

from xhtml.header.headers import Cookies
from xhtml.header.headers import Headers
from xhtml.locale.template import LocaleTemplate
from xpw import AuthInit
from xpw import BasicAuth
from xpw import SessionKeys
from xserver.http.proxy import HttpProxy
from xserver.http.proxy import RequestProxy
from xserver.http.proxy import ResponseProxy

BASE: str = os.path.dirname(__file__)


class AuthRequestProxy(RequestProxy):
    TEMPLATE = LocaleTemplate(os.path.join(BASE, "resources"))

    def __init__(self, target_url: str, lifetime: int = 86400, auth: Optional[BasicAuth] = None):  # noqa:E501
        self.__sessions: SessionKeys = SessionKeys(lifetime=lifetime)
        self.__auth: BasicAuth = auth or AuthInit.from_file()
        super().__init__(target_url)

    @property
    def auth(self) -> BasicAuth:
        return self.__auth

    @property
    def sessions(self) -> SessionKeys:
        return self.__sessions

    def authenticate(self, path: str, method: str, data: bytes,
                     headers: MutableMapping[str, str]
                     ) -> Optional[ResponseProxy]:
        if "localhost" in headers.get(Headers.HOST.value, ""):
            return None
        cookies: Cookies = Cookies(headers.get(Headers.COOKIE.value, ""))
        session_id: str = cookies.get("session_id")
        if not session_id:
            response = ResponseProxy.redirect(location=path)
            response.set_cookie("session_id", self.sessions.search().name)
            return response
        if self.sessions.verify(session_id):
            return None  # logged
        if method == "POST":
            form_data = parse_qs(data.decode("utf-8"))
            username = form_data.get("username", [""])[0]
            password = form_data.get("password", [""])[0]
            if password and self.auth.verify(username, password):
                self.sessions.sign_in(session_id)
                return ResponseProxy.redirect(location=path)
        context = self.TEMPLATE.search(headers.get("Accept-Language", "en"), "login").fill()  # noqa:E501
        content = self.TEMPLATE.seek("login.html").render(**context)
        response = ResponseProxy.make_ok_response(content.encode())
        return response

    def request(self, *args, **kwargs) -> ResponseProxy:
        return self.authenticate(*args, **kwargs) or super().request(*args, **kwargs)  # noqa:E501


def run(listen_address: Tuple[str, int], request_proxy: AuthRequestProxy):
    httpd = ThreadingHTTPServer(listen_address, lambda *args: HttpProxy(*args, request_proxy=request_proxy))  # noqa:E501
    httpd.serve_forever()


if __name__ == "__main__":
    run(("0.0.0.0", 3000), AuthRequestProxy("https://example.com/"))
