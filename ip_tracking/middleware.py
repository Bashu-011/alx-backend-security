from functools import cache
from django.http import HttpResponseForbidden
from .models import BlockedIP, RequestLog
from datetime import datetime

class IPLoggingMiddleware:
    """
    middleware that logs the IP address/timestamp/request_path
    """

    def __init__(self, get_response):
        self.get_response = get_response  #next layer of middleware

    def __call__(self, request):
        #before accessing the ciew
        ip = self.get_client_ip(request)
        path = request.path

        #log to db
        RequestLog.objects.create(
            ip_address=ip,
            path=path,
            timestamp=datetime.now()
        )

        #move to next midleware in the chain
        response = self.get_response(request)

        return response

    def get_client_ip(self, request):
        """
        get user IP from headers
        """
        x_forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR')
        if x_forwarded_for:
            ip = x_forwarded_for.split(',')[0]  #first IP in the list
        else:
            ip = request.META.get('REMOTE_ADDR', '')
        return ip
    

class IPLoggingAndBlockingMiddleware:
    def __init__(self, get_response):
        self.get_response = get_response
        self.geo = GeoIP2()

    def __call__(self, request):
        ip = self.get_client_ip(request)
        path = request.path

        #block blacklisted Ips
        if BlockedIP.objects.filter(ip_address=ip).exists():
            return HttpResponseForbidden("Access Denied: Your IP has been blocked.")

        #get geo date from geoIP
        geo_data = cache.get(ip)
        if not geo_data:
            try:
                geo_info = self.geo.city(ip)
                geo_data = {
                    'country': geo_info.get('country_name', ''),
                    'city': geo_info.get('city', '')
                }
                cache.set(ip, geo_data, 60 * 60 * 24)  #cache for 24hours
            except Exception:
                geo_data = {'country': '', 'city': ''}

        #log request
        RequestLog.objects.create(
            ip_address=ip,
            path=path,
            timestamp=datetime.now(),
            country=geo_data['country'],
            city=geo_data['city']
        )

        return self.get_response(request)

    def get_client_ip(self, request):
        x_forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR')
        if x_forwarded_for:
            ip = x_forwarded_for.split(',')[0]
        else:
            ip = request.META.get('REMOTE_ADDR', '')
        return ip
