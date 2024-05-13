from django.urls import re_path, path
from .views import group, create_group, list_groups,SingleGroup
from . import views

app_name = 'groups'

urlpatterns = [
    path('groups/', group, name='group'),
    path("all/", list_groups, name="all"),
    re_path("create", create_group, name="create"),
    re_path("groups/in/(?P<slug>[-\w]+)/$", SingleGroup.as_view(), name="single"),
    re_path("leave/(?P<slug>[-\w]+)/$", views.leave_group, name="leave"),
    path("join/<slug:slug>/", views.join_group, name='join'),
]
