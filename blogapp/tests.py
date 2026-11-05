from urllib.parse import quote

from django.contrib.auth.models import User
from django.test import TestCase, override_settings
from django.urls import reverse

from blogapp.models.Setting import Vul

# The project's default cache is memcached (core/settings.py:53-58) and
# SESSION_ENGINE is cache-backed, so tests pin a process-local cache.
LOCMEM_CACHE = {
    "default": {
        "BACKEND": "django.core.cache.backends.locmem.LocMemCache",
        "LOCATION": "login-redirect-tests",
    }
}

CREDENTIALS = {"username": "victim", "password": "correct-horse-battery-staple"}


@override_settings(CACHES=LOCMEM_CACHE)
class LoginRedirectTests(TestCase):
    """Regression tests for the post-authentication open redirect in loginView.post.

    ``loginView.post`` used to answer with ``redirect(request.GET["next"])``, so a
    crafted ``/login?next=https://attacker.example/`` link sent a victim who had just
    authenticated to an attacker-controlled origin.
    """

    @classmethod
    def setUpTestData(cls):
        # loginView.post and core.session_backend look these rows up by name and
        # index the result, so the view raises IndexError without them.
        for name in ("JWT", "JWT_Key_Confusion", "Deserialize"):
            Vul.objects.update_or_create(name=name, defaults={"status": False})
        User.objects.create_user(
            username=CREDENTIALS["username"], password=CREDENTIALS["password"]
        )

    def login(self, next_value=None):
        url = reverse("user_login")
        if next_value is not None:
            url = "{}?next={}".format(url, quote(next_value, safe=""))
        return self.client.post(url, CREDENTIALS)

    def assert_stays_local(self, next_value):
        response = self.login(next_value)
        self.assertEqual(response.status_code, 302)
        self.assertEqual(response["Location"], "/")
        # The repair must keep issuing the session cookie on the local response.
        self.assertIn("auth", response.cookies)

    def test_absolute_external_next_is_not_honoured(self):
        self.assert_stays_local("https://attacker.example/steal")

    def test_protocol_relative_next_is_not_honoured(self):
        self.assert_stays_local("//attacker.example/steal")

    def test_non_http_scheme_next_is_not_honoured(self):
        self.assert_stays_local("javascript:alert(document.cookie)")

    def test_local_next_is_still_honoured(self):
        response = self.login("/blog/")
        self.assertEqual(response.status_code, 302)
        self.assertEqual(response["Location"], "/blog/")

    def test_missing_next_falls_back_to_root(self):
        response = self.login()
        self.assertEqual(response.status_code, 302)
        self.assertEqual(response["Location"], "/")
