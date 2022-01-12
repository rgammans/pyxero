import json
import unittest
from mock import Mock, patch
from six.moves.urllib.parse import parse_qs, urlparse

from xero.pkce import (
    OAuth2PKCECredentials
)

class PKCECredentialsTest(unittest.TestCase):
    def setUp(self,):
        self.port = 9876
        self.client_id = "dummy"

    def test_initial_constructor(self,):   #white box
        credentials = OAuth2PKCECredentials(self.client_id, None, port=self.port, scope=[])
        ## Check length of verifier token is within Xero Needed lengths.
        self.assertGreater(len(credentials.verifier),43)
        self.assertLessEqual(len(credentials.verifier),128)

        ## Check the constructed callback url is where it supposed to be..
        self.assertTrue(credentials.callback_uri.startswith(f"http://localhost:{self.port}"))

    @patch("webbrowser.open")
    def test_logon_opens_a_page_at_zero(self,wbo):
        credentials = OAuth2PKCECredentials(self.client_id, None, port=self.port, scope=[])
        credentials.wait_for_callback = Mock()
        url_string = credentials.generate_url()
        url = urlparse(url_string)
        credentials.logon()
        wbo.assert_called()
        sent_url = urlparse(wbo.call_args[0][0])
        ## Check the URL Location matches.
        self.assertEqual(sent_url.scheme,url.scheme)
        self.assertEqual(sent_url.netloc,url.netloc)
        # but there are some appended 
        #self.assertEqual(sent_url.query,url.query)
        credentials.wait_for_callback.assert_called()
