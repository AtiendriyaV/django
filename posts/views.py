from django.contrib.auth.decorators import login_required
from django.shortcuts import render, get_object_or_404
from django.contrib import messages
from .models import Post
from .forms import PostForm
from accounts.models import UserProfile  # Import the UserProfile model
from django.shortcuts import render, redirect, get_object_or_404
from braces.views import SelectRelatedMixin
from . import models
from django.http import Http404
from django.views import generic
from django.contrib.auth import get_user_model
from django.http import JsonResponse

User = get_user_model()
from django.db import IntegrityError  # Import IntegrityError
from django.contrib.auth.decorators import login_required
from django.shortcuts import render, redirect
from braces.views import SelectRelatedMixin
from .models import Post
from accounts.models import UserProfile
from .forms import PostForm

@login_required
def create_post(request):
    # Retrieve or create UserProfile for the logged-in user
    user_profile, created = UserProfile.objects.get_or_create(user=request.user)
    print(f"user_profile: {user_profile}")  # Debug statement

    if not user_profile.otp_completed:
        user_profile.otp_completed = True
        user_profile.save()

    if request.method == 'POST':
        print("POST request received")  # Debug statement
        form = PostForm(request.POST)
        if form.is_valid():
            print("Form is valid")  # Debug statement
            try:
                post = form.save(commit=False)
                post.group = form.cleaned_data['group']
                post.user = request.user
                post.save()
                messages.success(request, "Post created successfully.")
                return redirect('posts:list_posts')  # Redirect to the post list page
            except IntegrityError:
                # Handle duplicate post creation error
                messages.error(request, "You've already created a post with the same message.")
                return redirect('posts:new_post')  # Redirect back to the new post creation page
    else:
        form = PostForm()

    return render(request, 'posts/new.html', {'form': form, 'user_profile': user_profile})


from django.contrib.auth.decorators import login_required
from django.shortcuts import render, redirect
from braces.views import SelectRelatedMixin
from .models import Post
from accounts.models import UserProfile
from .forms import PostForm

from django.contrib.auth.decorators import login_required
from django.shortcuts import render, redirect
from braces.views import SelectRelatedMixin
from .models import Post
from accounts.models import UserProfile
from .forms import PostForm

@login_required
def list_posts(request):
    # Use SelectRelatedMixin to select related fields
    posts = Post.objects.select_related("user", "group").all()

    # Retrieve or create UserProfile for the logged-in user
    user_profile, created = UserProfile.objects.get_or_create(user=request.user)
    print(f"user_profile: {user_profile}")  # Debug statement

    if not user_profile.otp_completed:
        user_profile.otp_completed = True
        user_profile.save()

    if request.method == 'POST':
        print("POST request received")  # Debug statement
        form = PostForm(request.POST)
        if form.is_valid():
            print("Form is valid")  # Debug statement
            # Create a new Post object with form data
            new_post = form.save(commit=False)
            # Set the user for the new post
            new_post.user = request.user
            # Save the new post
            new_post.save()
            # Redirect to the same page to avoid form resubmission
            return redirect('list_posts')
    else:
        form = PostForm()

    # If the request method is GET, render the list of posts with the form
    return render(request, 'posts/post_list.html', {'posts': posts, 'user_profile': user_profile, 'form': form})



@login_required
def post_detail(request, pk):
    post = get_object_or_404(Post, pk=pk)
    # Retrieve or create UserProfile for the logged-in user
    user_profile, created = UserProfile.objects.get_or_create(user=request.user)
    print(f"user_profile: {user_profile}")  # Debug statement
    return render(request, 'posts/post_detail.html', {'post': post, 'user_profile': user_profile})

@login_required
def delete_post(request, pk):
    post = get_object_or_404(Post, pk=pk)
    # Retrieve or create UserProfile for the logged-in user
    user_profile, created = UserProfile.objects.get_or_create(user=request.user)
    print(f"user_profile: {user_profile}")  # Debug statement

    if post.user == request.user:
        post.delete()
        messages.success(request, "Post deleted successfully.")
    else:
        messages.error(request, "You do not have permission to delete this post.")
    
    return redirect('posts:post_list')

@login_required
def fetch_posts(request):
    # Retrieve or create UserProfile for the logged-in user
    user_profile, created = UserProfile.objects.get_or_create(user=request.user)
    print(f"user_profile: {user_profile}")  # Debug statement

    posts = Post.objects.all().values('user', 'message', 'group')
    return JsonResponse(list(posts), safe=False)

@login_required
class UserPosts(generic.ListView):
    model = Post
    template_name = "posts/user_post_list.html"

    def get_queryset(self):
        try:
            self.post_user = User.objects.prefetch_related("posts").get(
                username__iexact=self.kwargs.get("username")
            )
        except User.DoesNotExist:
            print("User does not exist")  # Debug statement
            raise Http404
        else:
            return self.post_user.posts.all()

from django.urls import reverse_lazy
from django.views.generic.edit import CreateView
from .models import Post
@login_required
class PostList(CreateView):
    model = Post
    fields = ['user', 'group', 'message']  # Specify fields to include in the form
    template_name = 'post_create.html'  # Specify the template to use for rendering the form
    success_url = reverse_lazy('posts:post_base')  # Specify the URL to redirect to after successful form submission
