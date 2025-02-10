from django.db import models

# Create your models here.
class Student(models.Model):
    name = models.CharField(max_length=250, null=False, blank=False)
    department = models.CharField(max_length=250, null=False, blank=False)
    phone = models.CharField(max_length=16, null=False, blank=False)
    
    def __str__(self):
        return self.name