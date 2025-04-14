# coding:utf-8

from errno import ECANCELED
from http.server import ThreadingHTTPServer
import os
from typing import MutableMapping
from typing import Optional
from typing import Sequence
from typing import Tuple
from urllib.parse import parse_qs

from xhtml.header.headers import Cookies
from xhtml.header.headers import Headers
from xhtml.locale.template import LocaleTemplate
from xkits_command import ArgParser
from xkits_command import Command
from xkits_command import CommandArgument
from xkits_command import CommandExecutor
from xpw import AuthInit
from xpw import BasicAuth
from xpw import DEFAULT_CONFIG_FILE
from xpw import SessionKeys
from xserver.http.proxy import HttpProxy
from xserver.http.proxy import RequestProxy
from xserver.http.proxy import ResponseProxy

from xpw_locker.attribute import __description__
from xpw_locker.attribute import __urlhome__
from xpw_locker.attribute import __version__


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
        if path == "/favicon.ico":
            return None
        # if "localhost" in headers.get(Headers.HOST.value, ""):
        #     return None
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


@CommandArgument("locker-http", description=__description__)
def add_cmd(_arg: ArgParser):
    _arg.add_argument("--config", type=str, dest="config_file",
                      help="Authentication configuration", metavar="FILE",
                      default=os.getenv("CONFIG_FILE", DEFAULT_CONFIG_FILE))
    _arg.add_argument("--expires", type=int, dest="lifetime",
                      help="Session login interval hours", metavar="HOUR",
                      default=int(os.getenv("EXPIRES", "1")))
    _arg.add_argument("--target", type=str, dest="target_url",
                      help="Proxy target url", metavar="URL",
                      default=os.getenv("TARGET_URL", "http://localhost"))
    _arg.add_argument("--host", type=str, dest="listen_address",
                      help="Listen address", metavar="ADDR",
                      default=os.getenv("LISTEN_ADDRESS", "0.0.0.0"))
    _arg.add_argument("--port", type=int, dest="listen_port",
                      help="Listen port", metavar="PORT",
                      default=int(os.getenv("LISTEN_PORT", "3000")))


@CommandExecutor(add_cmd)
def run_cmd(cmds: Command) -> int:
    target_url: str = cmds.args.target_url
    lifetime: int = cmds.args.lifetime * 3600
    auth: BasicAuth = AuthInit.from_file(cmds.args.config_file)
    listen_address: Tuple[str, int] = (cmds.args.listen_address, cmds.args.listen_port)  # noqa:E501
    run(listen_address=listen_address, target_url=target_url, auth=auth, lifetime=lifetime)  # noqa:E501
    return ECANCELED


def main(argv: Optional[Sequence[str]] = None) -> int:
    cmds = Command()
    cmds.version = __version__
    return cmds.run(root=add_cmd, argv=argv, epilog=f"For more, please visit {__urlhome__}.")  # noqa:E501


if __name__ == "__main__":
    run(("0.0.0.0", 3000), "https://example.com/")
