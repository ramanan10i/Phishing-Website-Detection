from django.db import models

class Url(models.Model):
	url_value = models.CharField(max_length = 455)
	url_prob = models.CharField(max_length = 20)

# Create your models here.
