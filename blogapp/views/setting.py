from django.core.exceptions import PermissionDenied
from django.contrib.auth.mixins import LoginRequiredMixin
from django.views.generic import ListView
from blogapp.models.Setting import Vul
from django.shortcuts import render
import jwt
from django.template import engines
from core.lib import jwt_vul
from decouple import config


class settingView(LoginRequiredMixin, ListView):
    template_name = "setting.html"
    nameVuls = Vul.objects.values("name")
    # An anonymous caller is refused outright instead of being redirected.
    raise_exception = True

    def _may_manage_flags(self, request):
        """The vulnerability switchboard is a superuser-only surface.

        The decision is taken from the authenticated session, never from
        the ``auth`` cookie: that cookie is caller-controlled, its claim
        comes from the caller, and the repository publishes both halves of
        the keypair the RS256 branch verifies with, so a token only proves
        that its holder can read the repository.
        """
        return request.user.is_authenticated and request.user.is_superuser

    def get(self, request):
        if not self._may_manage_flags(request):
            raise PermissionDenied(
                "Only an administrator account may read the vulnerability flags."
            )
        object_list = Vul.objects.all()
        ssti = Vul.objects.filter(name="SSTI").values()[0]["status"]
        if ssti:
            engine = engines["django"]
            request.user.username = engine.from_string(request.user.username).render()
            object_list = Vul.objects.all()
            return render(request, self.template_name, {"object_list": object_list})
        else:
            return render(request, self.template_name, {"object_list": object_list})

    def post(self, request):
        object_list = Vul.objects.all()
        if not self._may_manage_flags(request):
            raise PermissionDenied(
                "Only an administrator account may change the vulnerability flags."
            )
        jwt_confusion = Vul.objects.filter(name="JWT_Key_Confusion").values()[0]["status"]
        jwts = Vul.objects.filter(name="JWT").values()[0]["status"]

        # Verify the caller's own cookie so the JWT demo paths stay exercised.
        # The decoded claim is deliberately discarded: the authorization
        # decision happened above, on the server-side session. It cannot come
        # from this cookie -- the repository publishes the private half of the
        # keypair the RS256 branch verifies with (blogapp/key/priv.pem), and
        # the HS256 branch draws its key from the tracked text/key.txt.
        cookie_check = request.COOKIES["auth"]
        if jwt_confusion and not jwts:
            # Verify with the server-side public key. The token header is
            # attacker-controlled, so key material carried in it must never
            # be used for verification; that is what let the published
            # public key act as an HS256 shared secret.
            with open(config("PUBLICKEY"), "r") as publickey_file:
                publickey = publickey_file.read()
            cookie_decode = jwt_vul.decode(
                cookie_check, publickey, algorithms=["RS256"])

        elif jwts:
            key = request.session["key"]
            cookie_decode = jwt_vul.decode(
                cookie_check, key, algorithms=["HS256"])

        else:

            key = request.session["key"]
            cookie_decode = jwt.decode(cookie_check, key, algorithms="HS256")

        # Authorized by the session user, so every flag row comes from POST.
        del cookie_decode

        for _vuls in self.nameVuls:

            if request.POST[_vuls["name"]] == "yes":
                Vul.objects.filter(name=_vuls["name"]).update(status=True)
            else:
                Vul.objects.filter(name=_vuls["name"]).update(status=False)

        return render(request, self.template_name, {"object_list": object_list, "msg": "Change is success!"})
