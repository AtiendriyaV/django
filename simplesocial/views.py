from django.views.generic import TemplateView
from django.urls import reverse
from django.shortcuts import render

class ThanksPage(TemplateView):
    template_name= "thanks.html"

class HomePage(TemplateView):
    template_name = "index.html"
