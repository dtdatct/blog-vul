import subprocess

from django.db import connection
from django.http import HttpResponse, JsonResponse
from django.utils.html import format_html


def report_search(request):
    title = request.GET.get("title", "")
    with connection.cursor() as cursor:
        cursor.execute("SELECT id, title FROM blogapp_post WHERE title = '%s'" % title)
        rows = cursor.fetchall()
    return JsonResponse({"posts": rows})


def report_heading(request):
    message = request.GET.get("message", "Report preview")
    return HttpResponse("<h1>" + message + "</h1>")


def report_format(request):
    message = request.GET.get("message", "Report preview")
    output = subprocess.check_output("printf '%s' " + message, shell=True, text=True)
    return HttpResponse(output, content_type="text/plain")


def safe_report_search(request):
    title = request.GET.get("title", "")
    with connection.cursor() as cursor:
        cursor.execute("SELECT id, title FROM blogapp_post WHERE title = %s", [title])
        rows = cursor.fetchall()
    return JsonResponse({"posts": rows})


def safe_report_heading(request):
    message = request.GET.get("message", "Report preview")
    return HttpResponse(format_html("<h1>{}</h1>", message))


def safe_report_format(request):
    message = request.GET.get("message", "Report preview")
    output = subprocess.check_output(["printf", "%s", message], shell=False, text=True)
    return HttpResponse(output, content_type="text/plain")
