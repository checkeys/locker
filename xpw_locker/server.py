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


class AuthRequestProxy(RequestProxy):

    def __init__(self, target_url: str, authentication: BasicAuth,
                 session_keys: SessionKeys, template: LocaleTemplate):
        self.__authentication: BasicAuth = authentication
        self.__sessions: SessionKeys = session_keys
        self.__template: LocaleTemplate = template
        super().__init__(target_url)

    @property
    def authentication(self) -> BasicAuth:
        return self.__authentication

    @property
    def sessions(self) -> SessionKeys:
        return self.__sessions

    @property
    def template(self) -> LocaleTemplate:
        return self.__template

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
            if password and self.authentication.verify(username, password):
                self.sessions.sign_in(session_id)
                return ResponseProxy.redirect(location=path)
        context = self.template.search(headers.get("Accept-Language", "en"), "login").fill()  # noqa:E501
        content = self.template.seek("login.html").render(**context)
        response = ResponseProxy.make_ok_response(content.encode())
        return response

    def request(self, *args, **kwargs) -> ResponseProxy:
        return self.authenticate(*args, **kwargs) or super().request(*args, **kwargs)  # noqa:E501

    @classmethod
    def create(cls, *args, **kwargs) -> "AuthRequestProxy":
        return cls(target_url=kwargs["target_url"],
                   authentication=kwargs["authentication"],
                   session_keys=kwargs["session_keys"],
                   template=kwargs["template"])


def run(listen_address: Tuple[str, int], target_url: str,
        auth: Optional[BasicAuth] = None, lifetime: int = 86400):
    base: str = os.path.dirname(__file__)
    authentication: BasicAuth = auth or AuthInit.from_file()
    session_keys: SessionKeys = SessionKeys(lifetime=lifetime)
    template: LocaleTemplate = LocaleTemplate(os.path.join(base, "resources"))
    httpd = ThreadingHTTPServer(listen_address, lambda *args: HttpProxy(
        *args, create_request_proxy=AuthRequestProxy.create,
        target_url=target_url, authentication=authentication,
        session_keys=session_keys, template=template))
    httpd.serve_forever()


if __name__ == "__main__":
    run(("0.0.0.0", 3000), "https://example.com/")
