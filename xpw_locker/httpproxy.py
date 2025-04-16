# coding:utf-8

from errno import ECANCELED
from http.server import ThreadingHTTPServer
import os
from typing import MutableMapping
from typing import Optional
from typing import Sequence
from typing import Tuple
from urllib.parse import parse_qs

from xhtml.header.cookie import Cookies
from xhtml.header.headers import Headers
from xhtml.locale.template import LocaleTemplate
from xkits_command import ArgParser
from xkits_command import Command
from xkits_command import CommandArgument
from xkits_command import CommandExecutor
from xpw import AuthInit
from xpw import BasicAuth
from xpw import DEFAULT_CONFIG_FILE
from xpw import Pass
from xpw import SessionKeys
from xserver.http.proxy import HttpProxy
from xserver.http.proxy import RequestProxy
from xserver.http.proxy import ResponseProxy

from xpw_locker.attribute import __description__
from xpw_locker.attribute import __official_name__
from xpw_locker.attribute import __urlhome__
from xpw_locker.attribute import __version__


class AuthRequestProxy(RequestProxy):

    def __init__(self,  # pylint:disable=R0913,R0917
                 target_url: str, authentication: BasicAuth,
                 session_keys: SessionKeys, template: LocaleTemplate,
                 api_token: Optional[str] = None):
        self.__authentication: BasicAuth = authentication
        self.__api_token: Optional[str] = api_token
        self.__sessions: SessionKeys = session_keys
        self.__template: LocaleTemplate = template
        super().__init__(target_url)

    @property
    def authentication(self) -> BasicAuth:
        return self.__authentication

    @property
    def api_token(self) -> Optional[str]:
        return self.__api_token

    @property
    def sessions(self) -> SessionKeys:
        return self.__sessions

    @property
    def template(self) -> LocaleTemplate:
        return self.__template

    def authenticate(self, path: str,  # pylint:disable=R0911,R0912,R0914
                     method: str, data: bytes,
                     headers: MutableMapping[str, str]
                     ) -> Optional[ResponseProxy]:
        if path == "/favicon.ico":
            return None

        # if "localhost" in headers.get(Headers.HOST.value, ""):
        #     return None

        authorization: str = headers.get(Headers.AUTHORIZATION.value, "")
        if authorization:
            from xhtml.header.authorization import \
                Authorization  # pylint:disable=import-outside-toplevel

            auth: Authorization.Auth = Authorization.paser(authorization)
            if auth.type == Authorization.Basic.TYPE:
                assert isinstance(auth, Authorization.Basic)
                if self.authentication.verify(auth.username, auth.password):
                    return None  # verified
            elif auth.type == Authorization.Bearer.TYPE:
                assert isinstance(auth, Authorization.Bearer)
                if self.api_token and auth.token == self.api_token:
                    return None  # verified
            elif auth.type == Authorization.APIKey.TYPE:
                assert isinstance(auth, Authorization.APIKey)
                if self.api_token and auth.key == self.api_token:
                    return None  # verified

        cookies: Cookies = Cookies(headers.get(Headers.COOKIE.value, ""))
        session_id: str = cookies.get("session_id")
        if not session_id:
            response = ResponseProxy.redirect(location=path)
            response.set_cookie("session_id", self.sessions.search().name)
            return response
        if self.sessions.verify(session_id):
            return None  # logged

        input_error_prompt: str = ""
        section = self.template.search(headers.get("Accept-Language", "en"), "login")  # noqa:E501
        if method == "POST":
            form_data = parse_qs(data.decode("utf-8"))
            username = form_data.get("username", [""])[0]
            password = form_data.get("password", [""])[0]
            if not password:
                input_error_prompt = section.get("input_password_is_null")
            elif self.authentication.verify(username, password):
                self.sessions.sign_in(session_id)
                return ResponseProxy.redirect(location=path)
            else:
                input_error_prompt = section.get("input_verify_error")
        context = section.fill(name=f"{__official_name__}(http)", version=__version__)  # noqa:E501
        context.setdefault("input_error_prompt", input_error_prompt)
        context.setdefault("url", __urlhome__)
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
                   template=kwargs["template"],
                   api_token=kwargs.get("api_token"))


def run(listen_address: Tuple[str, int], target_url: str,
        auth: Optional[BasicAuth] = None, token: Optional[str] = None,
        lifetime: int = 86400):
    base: str = os.path.dirname(__file__)
    authentication: BasicAuth = auth or AuthInit.from_file()
    session_keys: SessionKeys = SessionKeys(lifetime=lifetime)
    template: LocaleTemplate = LocaleTemplate(os.path.join(base, "resources"))
    httpd = ThreadingHTTPServer(listen_address, lambda *args: HttpProxy(
        *args, create_request_proxy=AuthRequestProxy.create,
        target_url=target_url, authentication=authentication,
        session_keys=session_keys, template=template, api_token=token))
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
    _arg.add_argument("--key", type=str, dest="api_token",
                      help="API key", metavar="KEY",
                      default=os.getenv("API_KEY"))


@CommandExecutor(add_cmd)
def run_cmd(cmds: Command) -> int:
    target_url: str = cmds.args.target_url
    lifetime: int = cmds.args.lifetime * 3600
    auth: BasicAuth = AuthInit.from_file(cmds.args.config_file)
    listen_address: Tuple[str, int] = (cmds.args.listen_address, cmds.args.listen_port)  # noqa:E501
    api_token: str = cmds.args.api_token or Pass.random_generate(32, Pass.CharacterSet.BASIC).value  # noqa:E501
    cmds.logger.info(f"API key: {api_token}")
    run(listen_address=listen_address,
        target_url=target_url,
        auth=auth, token=api_token,
        lifetime=lifetime)
    return ECANCELED


def main(argv: Optional[Sequence[str]] = None) -> int:
    cmds = Command()
    cmds.version = __version__
    return cmds.run(root=add_cmd, argv=argv, epilog=f"For more, please visit {__urlhome__}.")  # noqa:E501


if __name__ == "__main__":
    run(("0.0.0.0", 3000), "https://example.com/")
