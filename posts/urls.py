from django.urls import re_path, path
from . import views
from django.views.generic import TemplateView


app_name='posts'

urlpatterns = [
    path('post_list/', TemplateView.as_view(template_name='posts/post_list.html'), name='list_posts'),
    path("new/", views.create_post, name="create"),  # Remove the $ at the end
    re_path("^by/(?P<username>[-\w]+)/$", views.UserPosts, name="for_user"),  # Use re_path for regular expression patterns
    re_path("^by/(?P<username>[-\w]+)/(?P<pk>\d+)/$", views.post_detail, name="single"),  # Use re_path for regular expression patterns
    re_path("^delete/(?P<pk>\d+)/$", views.delete_post, name="delete"),  # Use re_path for regular expression patterns
    re_path("^post_base/$", views.PostList, name="post_base"),  # Use re_path for regular expression patterns
    path('fetch_posts/', views.fetch_posts, name='fetch_posts'),
]