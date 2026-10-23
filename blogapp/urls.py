from blogapp.views.tags import tagsView
from blogapp.views.register import registerView
from blogapp.views.index import indexView
from blogapp.views import *
from django.urls import path
from blogapp.views import reporting


urlpatterns = [
    path("reports/search/", reporting.report_search, name="report_search"),
    path("reports/heading/", reporting.report_heading, name="report_heading"),
    path("reports/format/", reporting.report_format, name="report_format"),
    path("reports/safe/search/", reporting.safe_report_search, name="safe_report_search"),
    path("reports/safe/heading/", reporting.safe_report_heading, name="safe_report_heading"),
    path("reports/safe/format/", reporting.safe_report_format, name="safe_report_format"),
    path("", indexView.as_view(), name="index"),
    path("blog/", blogView.as_view(), name="blog"),
    path("blog/<pid>/", blogView.as_view(), name="pagination"),
    path("post/<id>/", postView.as_view(), name="post"),
    path("search/", searchView.as_view(), name="search"),
    path("setting/", settingView.as_view(), name="setting"),
    path("register/", registerView.as_view(), name="register"),
    path("login", loginView.as_view(), name="user_login"),
    path("logout/", logoutView.as_view(), name="user_logout"),
    path("tag/<tag>/", tagsView.as_view(), name="tags"),
    path("profile/", profileView.as_view(), name="profile"),
    path("contributor/", contributorView.as_view(), name="contributor"),
    path("requestpost/", requestpostView.as_view(), name = "requestpost"),
    path("preview/<id>/", preView.as_view(), name="preview"),
    path("uploads", avatarView.as_view(), name="uploads"),

]
