from django.shortcuts import render, redirect, get_object_or_404
from django.contrib.auth import login, authenticate, logout, update_session_auth_hash
from django.contrib import messages
from django.contrib.auth.decorators import login_required
from django.contrib.auth.forms import PasswordChangeForm
from django.contrib.auth.models import User
from .forms import SignupForm, PostForm, EditProfileForm
from .models import Post, Comment, Like
import random, string
from django.core.mail import send_mail
from django.conf import settings
from django.utils import timezone
import datetime
from datetime import datetime
from django.http import HttpResponseBadRequest
from django.http import JsonResponse
from django.db.models import Count
from .forms import CommentForm
from .models import Comment
from django.db.models import Q


def home(request):
    categories = dict(Post._meta.get_field('category').choices)
    posts_by_category = {
        category: Post.objects.filter(category=key)
                              .annotate(
                                  like_count=Count('likes'),
                                  comment_count=Count('comments')
                              )
                              .order_by('?')[:5]  # Randomize posts
        for key, category in categories.items()
    }

    # if request.user.is_authenticated:
        # messages.success(request, f"Welcome back, {request.user.username}!")

    return render(request, 'home.html', {'posts_by_category': posts_by_category})
    
def login_view(request):
    if request.method == 'POST':
        username = request.POST['username']
        password = request.POST['password']
        user = authenticate(request, username=username, password=password)
        if user:
            login(request, user)
            if user.is_superuser:  # Check if the user is an admin
                return redirect('admin_dashboard')  # Redirect admin users to the admin dashboard
            return redirect('home')  # Redirect regular users to the homepage
        else:
            messages.error(request, 'Invalid username or password.')
    return render(request, 'login.html')

@login_required
def admin_dashboard(request):
    return render(request, 'admin_dashboard.html')

@login_required
def manage_users(request):
    users = User.objects.all()
    return render(request, 'manage_users.html', {'users': users})

@login_required
def delete_user(request, user_id):
    user = get_object_or_404(User, id=user_id)
    user.delete()
    return redirect('manage_users')

@login_required
def manage_posts(request):
    posts = Post.objects.all()
    comments = Comment.objects.all()
    return render(request, 'manage_posts.html', {'posts': posts, 'comments': comments})

@login_required
def delete_comment(request, comment_id):
    comment = get_object_or_404(Comment, id=comment_id)
    comment.delete()
    return redirect('manage_posts')

def is_admin(user):
    return user.is_staff or user.is_superuser

from django.shortcuts import get_object_or_404, redirect
from django.contrib.auth.decorators import login_required
from django.contrib import messages
from .models import Post

@login_required
def remove_post(request, post_id):
    print(f"remove_post called with post_id: {post_id}")  # Debugging log

    try:
        # Get the post or raise 404
        post = get_object_or_404(Post, id=post_id)
        print(f"Post found: {post.title} by {post.author.username}")  # Debugging log

        # Check if the user is authorized to delete
        if request.user == post.author or request.user.is_staff:
            print(f"User {request.user.username} authorized to delete.")  # Debugging log
            post.delete()
            messages.success(request, "Post deleted successfully.")
            return redirect('manage_posts')  # Replace with your desired redirect URL
        else:
            print(f"User {request.user.username} is not authorized to delete this post.")  # Debugging log
            messages.error(request, "You do not have permission to delete this post.")
            return redirect('manage_posts')
    except Exception as e:
        print(f"An error occurred: {e}")  # Debugging log for any exceptions
        messages.error(request, "Something went wrong.")
        return redirect('manage_posts')

# def admin_delete_post(request, post_id):
#     # Check if the user is an admin
#     if not request.user.is_staff:
#         return redirect('permission_denied')  # Ensure you have this view/URL

#     # Get the post or return a 404 if it doesn't exist
#     post = get_object_or_404(Post, id=post_id)

#     # Ensure this is a POST request for deletion
#     if request.method == 'POST':
#         post.delete()
#         return redirect('manage_posts')
    
#     # If not a POST request, show an error
#     messages.error(request, "Invalid deletion request.")
#     return redirect('manage_posts')
        
def signup_view(request):
    if request.method == 'POST':
        form = SignupForm(request.POST)
        if form.is_valid():
            user = form.save()
            login(request, user)
            return redirect('home')
    else:
        form = SignupForm()
    return render(request, 'register.html', {'form': form})

@login_required
def profile_view(request):
    user_posts = Post.objects.filter(author=request.user)
    return render(request, 'profile.html', {'posts': user_posts})

@login_required
def create_post(request):
    if request.method == 'POST':
        form = PostForm(request.POST)
        if form.is_valid():
            post = form.save(commit=False)
            post.author = request.user
            post.save()
            return redirect('home')
    else:
        form = PostForm()
    return render(request, 'create_post.html', {'form': form})

def logout_view(request):
    logout(request)
    return redirect('home')

@login_required
def edit_profile(request):
    if request.method == 'POST':
        form = EditProfileForm(request.POST, instance=request.user)
        if form.is_valid():
            form.save()
            return redirect('profile')
    else:
        form = EditProfileForm(instance=request.user)
    return render(request, 'edit_profile.html', {'form': form})

from django.contrib.auth import logout

from django.contrib.auth import logout
from django.contrib import messages

@login_required
def change_password(request):
    if request.method == 'POST':
        form = PasswordChangeForm(request.user, request.POST)
        if form.is_valid():
            form.save()  # Save the new password
            messages.success(request, 'Password successfully changed. Please log in again.')
            logout(request)  # Log the user out
            return redirect('home')  # Redirect to the homepage
        else:
            messages.error(request, 'Please correct the error below.')
    else:
        form = PasswordChangeForm(request.user)
    return render(request, 'change_password.html', {'form': form})

def post_detail(request, post_id):
    post = get_object_or_404(Post, id=post_id)
    comments = post.comments.all()
    is_liked = False  # Default value for unauthenticated users

    if request.user.is_authenticated:
        is_liked = post.likes.filter(user=request.user).exists()

    if request.method == "POST":
        if not request.user.is_authenticated:
            return redirect('login')  # Redirect anonymous users to login
        content = request.POST.get("content")
        if content:
            Comment.objects.create(post=post, user=request.user, content=content)
            return redirect('post_detail', post_id=post.id)

    context = {
        'post': post,
        'comments': comments,
        'is_liked': is_liked,
        'like_count': post.likes.count(),
        'comment_count': comments.count(),
    }
    return render(request, 'post_detail.html', context)

@login_required
def edit_post(request, post_id):
    post = get_object_or_404(Post, id=post_id, author=request.user)
    if request.method == 'POST':
        form = PostForm(request.POST, instance=post)
        if form.is_valid():
            form.save()
            return redirect('post_detail', post_id=post.id)
    else:
        form = PostForm(instance=post)
    return render(request, 'edit_post.html', {'form': form, 'post': post})
    
@login_required
def view_posts(request):
    posts = Post.objects.filter(author=request.user)
    return render(request, 'view_post.html', {'posts': posts})

def forgot_password(request):
    if request.method == 'POST':
        username = request.POST.get('username')
        email = request.POST.get('email')

        try:
            user = User.objects.get(username=username, email=email)
            otp = generate_otp()
            request.session['otp'] = otp
            request.session['reset_username'] = username  # Store the username in the session
            request.session['otp_timestamp'] = timezone.now().isoformat()

            send_otp_email(user.email, otp)
            messages.success(request, 'OTP has been sent to your email.')
            return redirect('verify_otp')
        except User.DoesNotExist:
            messages.error(request, 'User with the provided details not found.')

    return render(request, 'forgot_password.html')

def reset_password(request):
    if request.method == 'POST':
        new_password = request.POST.get('new_password')
        confirm_password = request.POST.get('confirm_password')

        # Check if passwords match
        if new_password != confirm_password:
            messages.error(request, 'Passwords do not match.')
            return redirect('reset_password')

        # Retrieve the username from the session
        reset_username = request.session.get('reset_username')
        if not reset_username:
            messages.error(request, 'Session expired. Please restart the reset process.')
            return redirect('forgot_password')

        try:
            # Get the user object
            user = User.objects.get(username=reset_username)
            # Set the new password
            user.set_password(new_password)
            user.save()  # Save to the database
            messages.success(request, 'Password reset successfully. You can now log in.')

            # Clear session data safely
            request.session.pop('reset_username', None)
            request.session.pop('otp', None)  # Prevent KeyError

            return redirect('login')

        except User.DoesNotExist:
            messages.error(request, 'User not found. Please try again.')
            return redirect('forgot_password')

    return render(request, 'reset_password.html')

def generate_otp():
    """Generate a random OTP (6 digits)."""
    otp = ''.join(random.choices(string.digits, k=6))  # Generates a 6-digit OTP
    return otp

def send_otp_email(user_email, otp):
    """Send OTP to user's email"""
    subject = "Your Password Reset OTP"
    message = f"Your OTP for password reset is {otp}. It will expire in 5 minutes."
    email_from = 'your_email@gmail.com'  # Your email address
    send_mail(subject, message, email_from, [user_email])

def verify_otp(request):
    if request.method == 'POST':
        entered_otp = request.POST.get('otp')
        stored_otp = request.session.get('otp')
        reset_username = request.session.get('reset_username')  # Get the username from the session

        if stored_otp and stored_otp == entered_otp:
            # OTP verified
            request.session['reset_username'] = reset_username  # Store the username for password reset
            del request.session['otp']  # Clear OTP
            return redirect('reset_password')  # Redirect to reset password page
        else:
            messages.error(request, 'Invalid OTP. Please try again.')
            return render(request, 'verify_otp.html')
    return render(request, 'verify_otp.html')

@login_required
def like_post(request, post_id):
    post = get_object_or_404(Post, id=post_id)
    user = request.user
    
    # Check if the user has already liked the post
    liked = Like.objects.filter(post=post, user=user).exists()
    
    if liked:
        # Unlike the post
        Like.objects.filter(post=post, user=user).delete()
    else:
        # Like the post
        Like.objects.create(post=post, user=user)
    
    return redirect('post_detail', post_id=post.id)

@login_required
def add_comment(request, post_id):
    # Get the post the comment is related to
    post = get_object_or_404(Post, id=post_id)

    if request.method == "POST":
        content = request.POST.get("content")
        if content:
            # Create a new comment and associate it with the logged-in user and the post
            Comment.objects.create(user=request.user, post=post, content=content)
        else:
            messages.error(request, "Comment content cannot be empty.")

    return redirect("post_detail", post_id=post.id)
    

@login_required
def liked_posts(request):
    # Fetch posts liked by the user
    liked_posts = Post.objects.filter(likes__user=request.user)
    return render(request, 'liked_posts.html', {'liked_posts': liked_posts})

from django.db import models
@login_required
def commented_posts(request):
    # Fetch posts that the logged-in user has commented on
    commented_posts = (
        Post.objects.filter(comments__user=request.user)
        .annotate(user_comment=models.F('comments__content'))
        .distinct()
    )
    
    # Fetch only the user's specific comments for the posts
    user_comments = {
        post.id: post.comments.filter(user=request.user).first()
        for post in commented_posts
    }

    return render(
        request,
        'commented_posts.html',
        {'commented_posts': commented_posts, 'user_comments': user_comments},
    )

def edit_comment(request, comment_id):
    comment = get_object_or_404(Comment, id=comment_id)
    
    # Ensure only the user who created the comment can edit it
    if request.user != comment.user:
        return redirect('post_detail', post_id=comment.post.id)
    
    if request.method == 'POST':
        form = CommentForm(request.POST, instance=comment)
        if form.is_valid():
            form.save()
            return redirect('post_detail', post_id=comment.post.id)
    else:
        form = CommentForm(instance=comment)
    
    return render(request, 'edit_comment.html', {'form': form})

def delete_post(request, post_id):
    post = get_object_or_404(Post, id=post_id)
    
    if request.method == 'POST':
        if request.user == post.author:  # Ensure that only the post author can delete it
            post.delete()
            return redirect('home')  # Redirect to user's profile after deletion
        else:
            messages.error(request, 'You are not authorized to delete this post.')
            return redirect('post_detail', post_id=post.id)
    
    return redirect('home')

@login_required
def delete_comment(request, comment_id):
    comment = get_object_or_404(Comment, id=comment_id)
    
    # Check if the user is an admin or the comment's author
    if request.user.is_staff or request.user == comment.user:
        comment.delete()
        # If admin, redirect to manage posts
        if request.user.is_staff:
            return redirect('manage_posts')
        # If regular user, redirect to the post detail
        else:
            return redirect('post_detail', post_id=comment.post.id)
    else:
        # If user is not authorized
        messages.error(request, "You are not authorized to delete this comment.")
        return redirect('post_detail', post_id=comment.post.id)

def search_blogs(request):
    query = request.GET.get('query', '')
    results = Post.objects.filter(
        Q(title__icontains=query) | Q(content__icontains=query)
    )
    return render(request, 'search_results.html', {'query': query, 'results': results})