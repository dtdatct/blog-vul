"""View-level regression test for the jwt_vul confusion at its consumer.

Code Audit finding 575cf6bc (audit 3c539c16), assessed at cac4f0a2. The
library-level suite (``test_jwt_vul_key_algorithm_binding.py``) pins the
mechanism; this test pins the *reachable path* the assessment traced:
``blogapp/views/setting.py`` verified an attacker-supplied token with key
material taken from that token's own header, and then trusted the decoded
``admin`` claim.

Requires the Django stack (``text/requirements.txt``), a cache the test can
reach, and the ``Vul`` rows the view reads. Run from the repository root::

    DATABASE_ENGINE=django.db.backends.sqlite3 DATABASE_NAME=/tmp/ct.sqlite3 \
    DATABASE_USER=x DATABASE_PASSWORD=x DATABASE_HOST=localhost DATABASE_PORT=5432 \
    <venv>/bin/python manage.py test tests -v 2
"""
import base64
import hashlib
import hmac
import json
import os

from django.contrib.auth.models import User
from django.test import Client, TestCase, override_settings
from django.urls import reverse

from blogapp.models.Setting import Vul
from blogapp.views.setting import settingView
from core.lib import jwt_vul
from core.lib.jwt_vul.exceptions import DecodeError

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
PUBLIC_KEY_PATH = os.path.join(REPO_ROOT, 'blogapp', 'key', 'pub.key')
PRIVATE_KEY_PATH = os.path.join(REPO_ROOT, 'blogapp', 'key', 'priv.pem')

# core/settings.py points CACHES at memcached, and SESSION_ENGINE is the
# cache-backed core.session_backend; tests need a reachable cache.
TEST_CACHES = {
    'default': {
        'BACKEND': 'django.core.cache.backends.locmem.LocMemCache',
        'LOCATION': 'ct-blog-vul-tests',
    }
}

ATTACKER_PAYLOAD = {'username': 'attacker', 'admin': True}
ALLOWED_MESSAGE = 'Change is success!'
DENIED_MESSAGE = "You don't have permission"


def _b64url(raw):
    return base64.urlsafe_b64encode(raw).replace(b'=', b'')


def forge_hs256(secret, payload, extra_header=None):
    """Hand-sign an HS256 token with *secret* verbatim (what an attacker does)."""
    header = {'typ': 'JWT', 'alg': 'HS256'}
    header.update(extra_header or {})
    secret_bytes = secret.encode('utf-8') if isinstance(secret, str) else secret
    signing_input = b'.'.join([
        _b64url(json.dumps(header, separators=(',', ':')).encode('utf-8')),
        _b64url(json.dumps(payload, separators=(',', ':')).encode('utf-8')),
    ])
    return signing_input + b'.' + _b64url(
        hmac.new(secret_bytes, signing_input, hashlib.sha256).digest())


@override_settings(CACHES=TEST_CACHES)
class SettingViewKeyConfusion(TestCase):
    """Vul writes must require a token verified against the server's own key."""

    @classmethod
    def setUpTestData(cls):
        for name in ('JWT', 'JWT_Key_Confusion', 'Deserialize', 'SSTI'):
            Vul.objects.get_or_create(name=name, defaults={'status': False})
        # The RS256-with-embedded-public-key branch that login.py drives.
        Vul.objects.filter(name='JWT').update(status=False)
        Vul.objects.filter(name='JWT_Key_Confusion').update(status=True)

    def setUp(self):
        with open(PUBLIC_KEY_PATH, 'r') as handle:
            self.public_pem = handle.read()
        with open(PRIVATE_KEY_PATH, 'r') as handle:
            self.private_pem = handle.read()

        self.admin = User.objects.create_superuser(
            'settingviewadmin', 'admin@example.com', 'S3cret-passw0rd')
        self.client = Client()
        self.client.force_login(self.admin)
        self.ssti_before = self._vul_status('SSTI')

    def _vul_status(self, name):
        return Vul.objects.get(name=name).status

    def _post_setting(self, auth_token):
        self.client.cookies['auth'] = auth_token
        # settingView.nameVuls is a class attribute whose queryset is
        # evaluated once, on the first request that reaches the write loop,
        # and then cached for the whole test process. Post the union of the
        # live rows and that roster so this test does not depend on which
        # test ran first.
        names = {row['name'] for row in Vul.objects.values('name')}
        names.update(row['name'] for row in settingView.nameVuls)
        return self.client.post(reverse('setting'),
                                data={name: 'yes' for name in names})

    def test_legitimate_rs256_cookie_is_accepted(self):
        """Negative control: the fix must not lock admins out."""
        token = jwt_vul.encode(
            {'username': self.admin.username, 'admin': True},
            self.private_pem, algorithm='RS256',
            headers={'publickey': self.public_pem})
        if isinstance(token, bytes):
            token = token.decode()
        response = self._post_setting(token)
        self.assertContains(response, ALLOWED_MESSAGE)
        self.assertNotEqual(self._vul_status('SSTI'), self.ssti_before)

    def test_hs256_token_signed_with_published_public_key_is_rejected(self):
        """The attack: the app's own public key used as an HS256 secret.

        The rejection arrives as an unhandled DecodeError from the pinned
        ``algorithms=["RS256"]`` verify call. Any invalid ``auth`` cookie raised
        out of this view before the change too; what matters for the finding is
        that the forged privilege claim is not honoured, so no Vul row is
        written. Making this a rendered 403 instead of an error is a separate
        improvement, not part of this repair.
        """
        token = forge_hs256(self.public_pem, ATTACKER_PAYLOAD,
                            extra_header={'publickey': self.public_pem})
        if isinstance(token, bytes):
            token = token.decode()
        with self.assertRaises(DecodeError):
            self._post_setting(token)
        self.assertEqual(self._vul_status('SSTI'), self.ssti_before)

    def test_hs256_token_signed_with_embedded_public_key_is_rejected(self):
        """Same attack while the cookie's own header supplies the key.

        This is the pre-fix shape where the consumer read the PEM out of the
        token header: whatever key the attacker names, the token must not pass
        an RS256-pinned verification against the server's public key.
        """
        other_secret = 'attacker-chosen-pem-ish-secret-material'
        token = forge_hs256(other_secret, ATTACKER_PAYLOAD,
                            extra_header={'publickey': other_secret})
        if isinstance(token, bytes):
            token = token.decode()
        with self.assertRaises(DecodeError):
            self._post_setting(token)
        self.assertEqual(self._vul_status('SSTI'), self.ssti_before)

    def test_unsigned_none_token_is_rejected_here(self):
        """The fixed consumer pins RS256, so an unsigned token fails too.

        This does NOT fix or dismiss the separately tracked 'none' finding
        (80d3426d); it only records that this consumer no longer accepts it.
        """
        header = _b64url(json.dumps({'typ': 'JWT', 'alg': 'none'},
                                    separators=(',', ':')).encode('utf-8'))
        payload = _b64url(json.dumps(ATTACKER_PAYLOAD,
                                     separators=(',', ':')).encode('utf-8'))
        token = header + b'.' + payload + b'.'
        if isinstance(token, bytes):
            token = token.decode()
        with self.assertRaises(DecodeError):
            self._post_setting(token)
        self.assertEqual(self._vul_status('SSTI'), self.ssti_before)
