"""View-level regression tests for the flag switchboard authorization.

Code Audit finding result 3a2c96be-b1df-4da7-a078-6b0abc354876 (audit
21a87971), assessed at 4efa851a91a6cbdcbc321f92ecf806b9acfaf267.

The assessment reports that ``blogapp/views/setting.py`` authorizes the
``Vul`` flag-update loop on the ``admin`` claim of the caller's own ``auth``
cookie, and that the claim is forgeable in the two reachable configurations:

* ``JWT_Key_Confusion`` on: the cookie is verified with the configured server
  public key, and the matching private key is tracked in the repository
  (``blogapp/key/priv.pem``), so anyone who can read the repo can mint
  ``{"admin": true}``;
* ``JWT`` on: the HMAC key is one line of the tracked ``text/key.txt``
  wordlist, so a caller recovers it from its own token offline.

Both flows are encoded below as regressions: a non-superuser session that
presents a self-minted cookie carrying ``admin: true`` must not rewrite a
single ``Vul`` row. The authorization decision must come from the
server-side session user instead.

Run from the repository root (needs ``text/requirements.txt``, a reachable
cache and the ``Vul`` rows the views read)::

    DATABASE_ENGINE=django.db.backends.sqlite3 DATABASE_NAME=/tmp/ct.sqlite3 \
    DATABASE_USER=x DATABASE_PASSWORD=x DATABASE_HOST=localhost DATABASE_PORT=5432 \
    <venv>/bin/python manage.py test tests -v 2
"""
import base64
import hashlib
import hmac
import json
import os
import random

from django.contrib.auth.models import User
from django.test import Client, TestCase, override_settings
from django.urls import reverse

from blogapp.models.Setting import Vul
from blogapp.views.setting import settingView

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
PUBLIC_KEY_PATH = os.path.join(REPO_ROOT, 'blogapp', 'key', 'pub.key')
PRIVATE_KEY_PATH = os.path.join(REPO_ROOT, 'blogapp', 'key', 'priv.pem')
WORDLIST_PATH = os.path.join(REPO_ROOT, 'text', 'key.txt')

# core/settings.py points CACHES at memcached and SESSION_ENGINE is the
# cache-backed core.session_backend, so tests need a cache they can reach.
TEST_CACHES = {
    'default': {
        'BACKEND': 'django.core.cache.backends.locmem.LocMemCache',
        'LOCATION': 'ct-blog-vul-setting-authz',
    }
}

FLAG_ROSTER = ('JWT', 'JWT_Key_Confusion', 'Deserialize', 'SSTI', 'XSS', 'CSRF')
FORGED_PAYLOAD = {'username': 'attacker', 'admin': True}
ALLOWED_MESSAGE = 'Change is success!'


def _b64url(raw):
    return base64.urlsafe_b64encode(raw).replace(b'=', b'')


def forge_hs256(secret, payload, algorithm='HS256'):
    """Hand-sign a token with *secret* verbatim, as an attacker would."""
    header = {'typ': 'JWT', 'alg': algorithm}
    secret_bytes = secret.encode('utf-8') if isinstance(secret, str) else secret
    signing_input = b'.'.join([
        _b64url(json.dumps(header, separators=(',', ':')).encode('utf-8')),
        _b64url(json.dumps(payload, separators=(',', ':')).encode('utf-8')),
    ])
    return (signing_input + b'.' + _b64url(
        hmac.new(secret_bytes, signing_input, hashlib.sha256).digest())).decode('ascii')


@override_settings(CACHES=TEST_CACHES)
class SettingViewAuthorization(TestCase):
    """The flag write must be decided by the server-side user, not the cookie."""

    @classmethod
    def setUpTestData(cls):
        for name in FLAG_ROSTER:
            Vul.objects.get_or_create(name=name, defaults={'status': False})

        # Seeded shapes from text/data.txt: 'admin' is a superuser, 'abc1' is
        # is_staff=True but is_superuser=False.
        cls.superuser = User.objects.create_superuser(
            'seedadmin', 'seedadmin@example.com', 'S3cret-passw0rd')
        cls.staff_user = User.objects.create_user(
            'seedabc1', 'seedabc1@example.com', 'S3cret-passw0rd')
        cls.staff_user.is_staff = True
        cls.staff_user.save()

    def setUp(self):
        with open(PUBLIC_KEY_PATH, 'r') as handle:
            self.public_pem = handle.read()
        with open(PRIVATE_KEY_PATH, 'r') as handle:
            self.private_pem = handle.read()

        self.client = Client()
        # Capture the baseline *after* the feature switches are set: the
        # switchboard state is part of what a denied request must leave alone.
        self.before = dict(Vul.objects.values_list('name', 'status'))

    # -- helpers ---------------------------------------------------------
    def _set_flags(self, jwt_flag, confusion_flag):
        Vul.objects.filter(name='JWT').update(status=jwt_flag)
        Vul.objects.filter(name='JWT_Key_Confusion').update(status=confusion_flag)
        # The switches are part of the protected state, so the baseline is
        # taken after they are arranged.
        self.before = dict(Vul.objects.values_list('name', 'status'))

    def _post_all_yes(self, cookie):
        if cookie is not None:
            self.client.cookies['auth'] = cookie
        # settingView.nameVuls is a class attribute evaluated when the URLconf
        # is imported, so its roster can lag the rows this test created. POST
        # the union: the view only reads the names it knows about.
        names = {row['name'] for row in Vul.objects.values('name')}
        names.update(row['name'] for row in settingView.nameVuls)
        return self.client.post(reverse('setting'),
                                data={name: 'yes' for name in names})

    def _flag_state(self):
        return dict(Vul.objects.values_list('name', 'status'))

    def _assert_no_flag_written(self):
        self.assertEqual(self._flag_state(), self.before,
                         'a denied request must not rewrite any Vul row')

    # -- the reported flows ----------------------------------------------
    def test_non_superuser_with_committed_private_key_cannot_write(self):
        """Flow 1: RS256 cookie minted with the tracked blogapp/key/priv.pem.

        The verification key is public and its private half is committed, so
        verification alone proves nothing about privilege.
        """
        self._set_flags(jwt_flag=False, confusion_flag=True)
        self.client.force_login(self.staff_user)
        token = _b64url(json.dumps({'typ': 'JWT', 'alg': 'RS256'},
                                  separators=(',', ':')).encode('utf-8')) + b'.'
        header = token + _b64url(json.dumps(FORGED_PAYLOAD,
                                            separators=(',', ':')).encode('utf-8'))
        # Sign with the committed private key, exactly as login.py does.
        from cryptography.hazmat.primitives import hashes, serialization
        from cryptography.hazmat.primitives.asymmetric import padding
        signing_input = header
        key = serialization.load_pem_private_key(
            self.private_pem.encode('utf-8'), password=None)
        signature = key.sign(signing_input, padding.PKCS1v15(), hashes.SHA256())
        cookie = (signing_input + b'.' + _b64url(signature)).decode('ascii')

        response = self._post_all_yes(cookie)
        self.assertEqual(response.status_code, 403)
        self._assert_no_flag_written()

    def test_non_superuser_with_wordlist_key_cannot_write(self):
        """Flow 2: HS256 cookie signed with a key taken from text/key.txt."""
        self._set_flags(jwt_flag=True, confusion_flag=False)
        self.client.force_login(self.staff_user)

        with open(WORDLIST_PATH, 'r') as handle:
            wordlist = [line.strip() for line in handle if line.strip()]
        weak_key = random.choice(wordlist)

        session = self.client.session
        session['key'] = weak_key
        session.save()

        cookie = forge_hs256(weak_key, FORGED_PAYLOAD)
        response = self._post_all_yes(cookie)
        self.assertEqual(response.status_code, 403)
        self._assert_no_flag_written()

    def test_anonymous_forged_cookie_cannot_write(self):
        """No session at all, with a self-signed admin cookie."""
        self._set_flags(jwt_flag=False, confusion_flag=True)
        cookie = forge_hs256(self.public_pem, FORGED_PAYLOAD)
        response = self._post_all_yes(cookie)
        self.assertIn(response.status_code, (302, 403))
        self._assert_no_flag_written()

    def test_anonymous_get_does_not_disclose_flag_table(self):
        """Flow 3: GET /setting/ rendered the whole Vul table unchecked."""
        response = self.client.get(reverse('setting'))
        body = response.content.decode('utf-8', 'replace')
        self.assertNotEqual(response.status_code, 200)
        self.assertNotIn('JWT_Key_Confusion', body)

    def test_authenticated_non_superuser_get_is_denied(self):
        self.client.force_login(self.staff_user)
        response = self.client.get(reverse('setting'))
        self.assertEqual(response.status_code, 403)

    # -- the fix must not lock the administrator out ----------------------
    def test_superuser_still_rewrites_flags(self):
        """Negative control: the legitimate administrator keeps working."""
        self._set_flags(jwt_flag=False, confusion_flag=True)
        self.client.force_login(self.superuser)
        token = _b64url(json.dumps({'typ': 'JWT', 'alg': 'RS256'},
                                  separators=(',', ':')).encode('utf-8')) + b'.'
        signing_input = token + _b64url(json.dumps(
            {'username': self.superuser.username, 'admin': True},
            separators=(',', ':')).encode('utf-8'))
        from cryptography.hazmat.primitives import hashes, serialization
        from cryptography.hazmat.primitives.asymmetric import padding
        key = serialization.load_pem_private_key(
            self.private_pem.encode('utf-8'), password=None)
        signature = key.sign(signing_input, padding.PKCS1v15(), hashes.SHA256())
        cookie = (signing_input + b'.' + _b64url(signature)).decode('ascii')

        response = self._post_all_yes(cookie)
        self.assertContains(response, ALLOWED_MESSAGE)
        self.assertEqual(self._flag_state()['SSTI'], True)

    def test_superuser_get_still_renders_the_table(self):
        self.client.force_login(self.superuser)
        response = self.client.get(reverse('setting'))
        self.assertEqual(response.status_code, 200)
        self.assertContains(response, 'JWT_Key_Confusion')
