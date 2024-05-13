from django.contrib import admin
from django.urls import path,re_path
from . import views
from django.conf.urls import include
from django.conf import settings
from accounts.views import WellView, add_item 
from accounts. views import delete_item
from accounts.views import item_table_view, item_list_endpoint, process_usage_form
urlpatterns = [
    path("admin/", admin.site.urls),
    re_path("^$", views.HomePage.as_view(), name="home"),
    path("accounts/", include(('accounts.urls', 'accounts'), namespace='accounts')),
    re_path("auth/", include('django.contrib.auth.urls')),
    re_path("thanks",views.ThanksPage.as_view(),name="thanks"),
    re_path("^posts/", include("posts.urls", namespace="posts")),
    re_path("^groups/",include("groups.urls", namespace="groups")),
    path('well/', WellView.as_view(), name='well'),
    path('add_item/', add_item, name='add_item'),
    path('delete_item/<int:item_id>/', delete_item, name='delete_item'),
    path('item_table/', item_table_view, name='item_table'),
    path('item_list/', item_list_endpoint, name='item_list_endpoint'),
    path('process_usage_form/', process_usage_form, name='process_usage_form'),
]