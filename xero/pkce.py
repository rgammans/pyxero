import http.server
import threading
import webbrowser
import secrets
import hashlib
import base64
import urllib.parse
from functools import partial
import requests

import xero.auth as xa
from xero.constants import XERO_OAUTH2_TOKEN_URL

import logging

logger = logging.getLogger(__name__)

class AuthReceiver(http.server.BaseHTTPRequestHandler):
    """ This is an http server running on localhost, to which
    Xero will redirect the browser after auth, from which we
    can collect the auto profile Xero provides
    """
    def __init__(self, credmanager , *args,**kwargs):
        self.credmanager = credmanager
        super().__init__(*args,**kwargs)

    @classmethod
    def close_server(s):
        s.shutdown()

    def do_GET(self,*args):
        logger.debug("rx GET",self.path,args)
        request = urllib.parse.urlparse(self.path)
        path = request.path
        params = urllib.parse.parse_qs(request.query)

        if path == "/callback":
            self.credmanager.verify_url(params,self)
        else:
            self.send_error_page("Unknown endpoint")

    def send_error_page(self,error):
        """Display an Error page"""
        logger.error("Error:",error)

    def send_accces_ok(self,):
        """Display a success page"""
        logger.info("LOGIN SUCCESS")
        threading.Thread(target=AuthReceiver.close_server,
                         args=(self.server,)
        ).start()

    def send_accces_denied(self,):
        """Show a login denied page"""
        logger.info("LOGIN FAILURE")
        

    def shutdown(self):
        """Launch a thread to wait for server shutdown"""
        threading.Thread(target=AuthReceiver.close_server,
                         args=(self.server,)
        ).start()


class OAuth2PKCECredentials(xa.OAuth2Credentials):
    """An object wrapping the PKCE credential flow for Xero access.

    Usage:
      1) Construct an `OAuth2Credentials` instance:

        >>> from xero.pkce import OAuth2PKCECredentials
        >>> credentials = OAuth2Credentials(client_id,None, port=8080,
        >>>                                 scope=scope)

        A webserver will be setup to listen on the provded port 
        number which is used for the AUth callback.

      2) Send the login request.
        >>> credentials.logon()

        This will open a browser window which will naviage to a Xero
        login page. The Use should grant your application access (or not),
        and will be redirected to a locally running webserver to capture
        the auth tokens.

      3) Verify the credentials using the full URL redirected to, including querystring:
         >>> credentials.verify(full_url_with_querystring)

      4) Use the credentials. It is usually necessary to set the tenant_id (Xero
         organisation id) to specify the organisation against which the queries should
         run:
         >>> from xero import Xero
         >>> credentials.set_default_tenant()
         >>> xero = Xero(credentials)
         >>> xero.contacts.all()
        ...

         To use a different organisation, set credentials.tenant_id:
         >>> tenants = credentials.get_tenants()
         >>> credentials.tenant_id = tenants[1]['tenantId']

      5) If a refresh token is available, it can be used to generate a new token:
         >>> if credentials.expired():
         >>>     credentials.refresh()

        Note that in order for tokens to be refreshable, Xero API requires
        `offline_access` to be included in the scope.

    """
    def __init__(self,*args,**kwargs):
        self.port = kwargs.pop('port',8081)
        self.runserver = kwargs.pop('handle_flow',True)
        # Xero requires between 43 adn 128 bytes, it fails
        # with invlaid grant if this is not long enough
        self.verifier = kwargs.pop('verifier',secrets.token_urlsafe(64))
        self.error = None
        if isinstance(self.verifier,str):
            self.verifier = self.verifier.encode('ascii')
        kwargs.setdefault('callback_uri',f"http://localhost:{self.port}/callback")
        super().__init__(*args,**kwargs)

    def logon(self,):
        """Start the login process.
        Returns once a call back has been received
        """
        challenge = str(base64.urlsafe_b64encode(hashlib.sha256(self.verifier).digest())[:-1],'ascii')
        url_base = super().generate_url()
        webbrowser.open(url_base +f"&code_challenge={challenge}&code_challenge_method=S256")
        self.wait_for_callback()

    def wait_for_callback(self,):
        listen_to = ('',self.port)
        s = http.server.HTTPServer(listen_to, partial(AuthReceiver,self) )
        s.serve_forever()
        if self.error:
            raise xa.XeroAccessDenied(self.error)

    def verify_url(self,params,reqhandler):
        """Verify the auth information in a callback url"""
        error = params.get('error',None)
        if error:
            self.handle_error(error,reqhandler)
            return

        if params['state'][0] != self.state['auth_state']:
            self.handle_error("State Mismatch",reqhandler)
            return

        code = params.get('code',None)
        if code:
            try:
                self.get_token(code[0])
            except Exception as e:
                self.error = e
                reqhandler.send_error_page(str(e))
                reqhandler.shutdown()

            reqhandler.send_accces_ok()


    def get_token(self,code):
        """Does the third leg, to get the actual auth token from Xero,
        once the authentication has been 'approved' by the user
        """
        resp = requests.post(
             url=XERO_OAUTH2_TOKEN_URL,
             data={
                 'grant_type': 'authorization_code',
                 'client_id': self.client_id,
                 'redirect_uri': self.callback_uri,
                 'code': code,
                 'code_verifier': self.verifier
             }
         )
        respdata = resp.json()
        error = respdata.get('error',None)
        if error:
            raise RuntimeError(error)

        self._init_oauth(respdata)

    def handle_error(self,msg,handler):
        self.error = RuntimeError(msg)
        handler.send_error_page(msg)
        handler.shutdown()

def check():
    client_id = "D0B17846B8844C85A99173E17AC9EA45"
    credentials = OAuth2PKCECredentials(client_id, None,)
    credentials.logon()
    print(credentials.get_tenants())
    from xero import Xero
    xero = Xero(credentials)
    credentials.set_default_tenant()
    print(credentials.tenant_id)

if __name__ == "__main__":
    #run the demo code
    check()
