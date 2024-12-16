from django.urls import path
from . import views

urlpatterns = [
    # Main pages
    path('', views.home, name='home'),
    path('login/', views.login_view, name='login'),
    path('signup/', views.signup_view, name='signup'),
    path('logout/', views.logout_view, name='logout'),
    path('search/', views.search_blogs, name='search_blogs'),

    # Admin
    path('admin-dashboard/', views.admin_dashboard, name='admin_dashboard'),
    path('manage-users/', views.manage_users, name='manage_users'),
    path('manage-posts/', views.manage_posts, name='manage_posts'),
    path('delete-user/<int:user_id>/', views.delete_user, name='delete_user'),
    path('delete-comment/<int:comment_id>/', views.delete_comment, name='delete_comment'),
    # path('post/<int:post_id>/delete/', views.admin_delete_post, name='admin_delete_post'),
   path('post/<int:post_id>/delete/', views.remove_post, name='remove_post'),
    # Profile related
    path('profile/', views.profile_view, name='profile'),
    path('profile/edit/', views.edit_profile, name='edit_profile'),
    path('profile/change-password/', views.change_password, name='change_password'),
    path('profile/posts/', views.view_posts, name='view_posts'),
    path('forgot-password/', views.forgot_password, name='forgot_password'),
    path('verify-otp/', views.verify_otp, name='verify_otp'),
    path('reset-password/', views.reset_password, name='reset_password'),
    path('profile/liked-posts/', views.liked_posts, name='liked_posts'),
    path('profile/commented-posts/', views.commented_posts, name='commented_posts'),
    
    # Post related
    path('create_post/', views.create_post, name='create_post'),
    path('post/<int:post_id>/', views.post_detail, name='post_detail'),
    path('post/<int:post_id>/edit/', views.edit_post, name='edit_post'),
    path('post/<int:post_id>/delete/', views.delete_post, name='delete_post'),
    path('post/<int:post_id>/like/', views.like_post, name='like_post'),
    path('post/<int:post_id>/comment/', views.add_comment, name='add_comment'),
    path('edit-comment/<int:comment_id>/', views.edit_comment, name='edit_comment'),
    path('delete-comment/<int:comment_id>/', views.delete_comment, name='delete_comment'),  # Correct: comment_id
    path('post/<int:post_id>/user-delete/', views.delete_post, name='delete_post'),
]
