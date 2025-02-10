from django.shortcuts import render,redirect, get_object_or_404
from django.template.loader import render_to_string
from django.utils.decorators import method_decorator
from django.views.decorators.cache import never_cache
from django.contrib.auth.mixins import LoginRequiredMixin
from django.urls import reverse_lazy
from django.contrib import messages
from django.views import generic
from django.http import HttpResponseRedirect, JsonResponse

from tasks.forms import StudentForm

# Create your views here.
@method_decorator(never_cache, name='dispatch')
class HomeView(LoginRequiredMixin, generic.View):
    login_url = reverse_lazy('sign')
    def get(self, request):
        form = StudentForm
        return render(request, 'home.html', {'form': form})
    