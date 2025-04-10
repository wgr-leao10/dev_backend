from django.db import models

# Create your models here.
class Post(models.Model):
    titulo = models.CharField(max_length=100)
    conteudo = models.TextField()
    data_publicacao=models.DateTimeField(auto_now_add=True)
    
    def__str__(self):
    return self.titulo