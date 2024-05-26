from django.urls import re_path,path
from django.contrib.auth import views as auth_views
from . import views
from accounts.views import logout_view
from accounts.views import otp_view
from accounts.views import WellView,add_item
from accounts.views import add_item
from .views import delete_item
from simplesocial.views import ThanksPage
from django.contrib import admin
from accounts.views import item_table_view, item_list_endpoint


urlpatterns = [
    path('login/', views. login_view.as_view(), name='login'),
    path('logout/', views.logout_view, name='logout'),
    re_path("signup/$", views.SignUp.as_view(), name="signup"),
    path('password_change/',auth_views.PasswordChangeView.as_view(template_name='accounts/password_change_form.html'),name='password_change'),
    path('password_change/done/',auth_views.PasswordChangeDoneView.as_view(template_name='accounts/password_change_done.html'),name='password_change_done'),
    path('password_reset/', auth_views.PasswordResetView.as_view(template_name='accounts/password_reset_form.html'), name='password_reset'),
    path('passsword_reset/done',auth_views.PasswordResetDoneView.as_view(template_name='accounts/password_reset_done.html'),name='password_reset_done'),
    path('reset/<uidb64>/<token>/', auth_views.PasswordResetConfirmView.as_view(template_name='accounts/password_reset_confirm.html'), name='password_reset_confirm'),
    path('reset/done/',auth_views.PasswordResetCompleteView.as_view(template_name='accounts/password_reset_complete.html'),name="password_reset_complete"),
    re_path("thanks",ThanksPage.as_view(),name="thanks"),
    path('well', WellView.as_view(), name='well'),
    path('admin/', admin.site.urls),
    path('loginotp/', otp_view.as_view(), name='loginotp'),
    path('add_item/', add_item, name='add_item'),
    path('delete_item/<int:item_id>/', delete_item, name='delete_item'),
    path('item_table/', item_table_view, name='item_table'),
    path('item_list/', item_list_endpoint, name='item_list_endpoint'),
    path('get_latest_items/', views.get_latest_items, name='get_latest_items'),
    path('process_usage_form/', views.process_usage_form, name='process_usage_form'),
    path('favicon.ico', views.favicon_view),
    path('upload_file/', views.upload_file, name='upload_file'),
    path('Data/', views.Data, name='Data'),
    path('chart/', views.chart, name='chart'),
    path('audit/', views.audit_view, name='audit'),
    path('review/', views.review_view, name='review'),
    ]
