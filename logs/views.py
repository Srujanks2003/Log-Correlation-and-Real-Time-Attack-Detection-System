from django.http import JsonResponse
from django.db.models import Count
from .models import LogEntry,Alert
from django.db.models import Count, Q, F, FloatField, ExpressionWrapper
from django.db.models import Count
from django.shortcuts import render
from django.shortcuts import render, redirect
from django.contrib import messages
import re
from datetime import datetime
from .models import LogEntry
from django.db.models import Q
from django.utils import timezone
from datetime import timedelta
import json

#--------------------------------------------------------------------------------
def suspicious_ips(request):
    suspicious = (
        LogEntry.objects
        .values('ip_address')
        .annotate(
            total_requests=Count('id'),
            failed_requests=Count('id', filter=Q(status_code__in=[401, 403])),
        )
        .annotate(
            failure_rate=ExpressionWrapper(
                F('failed_requests') * 100.0 / F('total_requests'),
                output_field=FloatField()
            )
        )
        .filter(failed_requests__gt=10)
        .order_by('-failure_rate')
    )

    return JsonResponse(list(suspicious), safe=False)


#------------------------------------------------------------------------------

""" BRUTE FORCE METHOD"""

from django.db.models import Max
from datetime import timedelta
def brute_force_recent(request):
    # Get latest log timestamp from dataset
    latest_time = LogEntry.objects.aggregate(Max('timestamp'))['timestamp__max']

    if not latest_time:
        return JsonResponse({"message": "No logs found"}, safe=False)

    five_minutes_before = latest_time - timedelta(minutes=5)

    suspicious = (
        LogEntry.objects
        .filter(
            status_code__in=[401, 403],
            timestamp__gte=five_minutes_before,
            timestamp__lte=latest_time
        )
        .values('ip_address')
        .annotate(fail_count=Count('id'))
        .filter(fail_count__gt=2)
        .order_by('-fail_count')
    )

    return JsonResponse(list(suspicious), safe=False)


#--------------------------------------------------------------------------------------


"""TESTING OF BRUTE FORCE METHOD"""


from django.db.models import Max, Count
from datetime import timedelta
from django.http import JsonResponse

def debug_last_5_minutes(request):
    latest_time = LogEntry.objects.aggregate(Max('timestamp'))['timestamp__max']

    five_minutes_before = latest_time - timedelta(minutes=5)

    data = (
        LogEntry.objects
        .filter(timestamp__gte=five_minutes_before, timestamp__lte=latest_time)
        .values('ip_address', 'status_code')
        .annotate(count=Count('id'))
        .order_by('-count')
    )

    return JsonResponse(list(data)[:20], safe=False)

#----------------------------------------------------------------------------------------


""" Top Attackers Analytics API """
def top_ips(request):
    top = (
        LogEntry.objects
        .values('ip_address')
        .annotate(total_requests=Count('id'))
        .order_by('-total_requests')[:10]
    )

    return JsonResponse(list(top), safe=False)


#-------------------------------------------------------------------------------
"""Status Code Analytics API"""
def status_distribution(request):
    data = (
        LogEntry.objects
        .values('status_code')
        .annotate(count=Count('id'))
        .order_by('-count')
    )

    return JsonResponse(list(data), safe=False)
#------------------------------------------------------------------------------------------

"""CREATION OF API TO VIEW ALERTS"""

def alerts_list(request):
    alerts = Alert.objects.all().order_by('-created_at')
    data = [
        {
            "ip_address": alert.ip_address,
            "alert_type": alert.alert_type,
            "message": alert.message,
            "created_at": alert.created_at,
        }
        for alert in alerts
    ]
    return JsonResponse(data, safe=False)


#----------------------------------------------------------------------------------------------

""" DASHBOARD VIEW"""

from django.contrib import messages
import re
from datetime import datetime
from django.db.models import Count
from logs.models import LogEntry, Alert


log_pattern = re.compile(
    r'(\d+\.\d+\.\d+\.\d+) - - \[(.*?)\] "(.*?) (.*?) HTTP/.*?" (\d+) (\d+)'
)
def dashboard(request):

    formatted_summary = []
    show_summary = False

    # ------------------HANDLE FILE UPLOAD-----------
    
    
    if request.method == "POST":
        file = request.FILES.get("log_file")

        if file:
            show_summary = True
            upload_start_time = timezone.now()

            for line in file:
                line = line.decode("utf-8")
                match = log_pattern.match(line)

                if match:
                    ip = match.group(1)
                    time_str = match.group(2)
                    method = match.group(3)
                    url = match.group(4)
                    status = int(match.group(5))
                    size = int(match.group(6))

                    timestamp = datetime.strptime(time_str, "%d/%b/%Y:%H:%M:%S %z")

                    LogEntry.objects.create(
                        ip_address=ip,
                        timestamp=timestamp,
                        method=method,
                        url=url,
                        status_code=status,
                        response_size=size
                    )

            messages.success(request, "Logs uploaded and analyzed successfully.")

            # Summary ONLY for this upload
            upload_alerts = Alert.objects.filter(
                created_at__gte=upload_start_time
            )

            for item in upload_alerts.values('alert_type').annotate(count=Count('id')):
                formatted_summary.append({
                    "alert_type": item['alert_type'],
                    "count": item['count']
                })

    # -----------------------------SYSTEM STATUS (Recent High Only)--------------------
    
    time_threshold = timezone.now() - timedelta(minutes=10)

    recent_high_alerts = Alert.objects.filter(
        severity='High',
        is_resolved=False,
        created_at__gte=time_threshold
    ).exists()

    system_status = "UNDER ATTACK" if recent_high_alerts else "SYSTEM SAFE"

    # -----------------------------Dashboard Stats---------------------
    
    
    total_logs = LogEntry.objects.count()
    total_alerts = Alert.objects.count()

    top_ips = (
        LogEntry.objects
        .values('ip_address')
        .annotate(total=Count('id'))
        .order_by('-total')[:5]
    )

    recent_alerts = Alert.objects.all().order_by('-created_at')[:5]

    # -----------------------------Chart Data ---------------------
    
    
    session_labels = []
    session_counts = []

    if show_summary:
        for item in formatted_summary:
            session_labels.append(item["alert_type"])
            session_counts.append(item["count"])

    overall_attacks = (
        Alert.objects
        .values('alert_type')
        .annotate(count=Count('id'))
    )

    overall_labels = [a['alert_type'] for a in overall_attacks]
    overall_counts = [a['count'] for a in overall_attacks]

    context = {
        'total_logs': total_logs,
        'total_alerts': total_alerts,
        'top_ips': top_ips,
        'recent_alerts': recent_alerts,
        'system_status': system_status,
        'attack_summary': formatted_summary,
        'show_summary': show_summary,
        'session_labels': json.dumps(session_labels),
        'session_counts': json.dumps(session_counts),
        'overall_labels': json.dumps(overall_labels),
        'overall_counts': json.dumps(overall_counts),
    }

    return render(request, 'logs/dashboard.html', context)

#-----------------------------------------------------------------------------------
"""Create Upload Form View"""

log_pattern = re.compile(
    r'(\d+\.\d+\.\d+\.\d+) - - \[(.*?)\] "(.*?) (.*?) HTTP/.*?" (\d+) (\d+)'
)


def upload_logs(request):
    if request.method == 'POST':
        file = request.FILES.get('log_file')

        if not file:
            messages.error(request, "No file uploaded.")
            return redirect('upload_logs')

        for line in file:
            line = line.decode('utf-8')
            match = log_pattern.match(line)

            if match:
                ip = match.group(1)
                time_str = match.group(2)
                method = match.group(3)
                url = match.group(4)
                status = int(match.group(5))
                size = int(match.group(6))

                timestamp = datetime.strptime(time_str, "%d/%b/%Y:%H:%M:%S %z")

                LogEntry.objects.create(
                    ip_address=ip,
                    timestamp=timestamp,
                    method=method,
                    url=url,
                    status_code=status,
                    response_size=size
                )

        messages.success(request, "Logs uploaded and analyzed successfully.")
        return redirect('dashboard')

    return render(request, 'logs/upload.html')


#-------------------------------------------------------------------------------------------
"""Add Resolve View"""

from django.shortcuts import get_object_or_404
from django.http import HttpResponseRedirect
from django.urls import reverse

def resolve_alert(request, alert_id):
    alert = get_object_or_404(Alert, id=alert_id)
    alert.is_resolved = True
    alert.save()
    return HttpResponseRedirect(reverse('dashboard'))