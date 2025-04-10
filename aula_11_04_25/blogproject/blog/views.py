from django.shortcuts import render

# Create your views here.
from django.shortcuts import render
from .models import Post


def listar_postagens(request):
    posts = Post.objects.all()
    return render(request, 'blog/lista.html', {'posts': posts})
