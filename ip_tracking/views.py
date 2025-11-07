from django.shortcuts import render
from django.http import JsonResponse
from django.contrib.auth import authenticate, login
from ratelimit.decorators import ratelimit

#5 reqs/min for anonymous/new users
#10 reqs /min for authenticated users
@ratelimit(key='ip', rate='5/m', method='POST', block=True)
@ratelimit(key='user_or_ip', rate='10/m', method='POST', block=True)
def login_view(request):
    if request.method == 'POST':
        username = request.POST.get('username')
        password = request.POST.get('password')
        user = authenticate(request, username=username, password=password)
        if user is not None:
            login(request, user)
            return JsonResponse({'message': 'Login successful'})
        else:
            return JsonResponse({'error': 'Invalid credentials'}, status=401)

    return JsonResponse({'error': 'POST required'}, status=405)