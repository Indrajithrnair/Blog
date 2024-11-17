from django.db import models
from django.contrib.auth.models import User


class Profile(models.Model):
    user = models.OneToOneField(User, on_delete=models.CASCADE)
    bio = models.TextField(max_length=500, blank=True)
    profile_picture = models.ImageField(upload_to='profile_pics/', blank=True)

    def __str__(self):
        return f"{self.user.username}'s Profile"


class Post(models.Model):
    author = models.ForeignKey(User, on_delete=models.CASCADE)  # Link each post to a user
    title = models.CharField(max_length=100)
    content = models.TextField()
    category = models.CharField(
        max_length=50,
        choices=[
            ('tech', 'Technology'),
            ('life', 'Lifestyle'),
            ('food', 'Food'),
            ('travel', 'Travel'),
        ],
        default='tech',
    )
    created_at = models.DateTimeField(auto_now_add=True)  # Automatically set when a post is created

    def __str__(self):
        return self.title


class Like(models.Model):
    post = models.ForeignKey(Post, on_delete=models.CASCADE, related_name='likes')  # Relate likes to a post
    user = models.ForeignKey(User, on_delete=models.CASCADE)  # User who liked the post
    liked_at = models.DateTimeField(auto_now_add=True)  # Timestamp of like

    def __str__(self):
        return f"{self.user.username} liked {self.post.title}"


class Comment(models.Model):
    post = models.ForeignKey(Post, on_delete=models.CASCADE, related_name='comments')
    user = models.ForeignKey(User, on_delete=models.CASCADE)
    content = models.TextField()
    commented_at = models.DateTimeField(auto_now_add=True)


    def __str__(self):
        return f"{self.user.username} commented on {self.post.title}"