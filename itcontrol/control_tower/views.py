import os
import json
import re
import html
import shutil
import subprocess
from datetime import datetime, timezone, timedelta
from django.shortcuts import render, redirect, get_object_or_404
from django.http import JsonResponse, HttpResponse, HttpResponseBadRequest, HttpResponseForbidden, HttpResponseNotFound
from django.views.decorators.csrf import csrf_exempt
from django.utils import timezone as dj_timezone

from .models import Endpoint, Job, AuditLog, Alert, AlertCondition, AppSetting, AppUsage, AppUsageTotal

API_KEY = os.environ.get('ITOPS_API_KEY', 'change-this-local-dev-key')

ACTIONS = {
    'hardware': {
        'refresh_inventory': 'Refresh Hardware Inventory',
        'hardware_health': 'Check Hardware Health',
        'disk_report': 'Collect Disk Details'
    },
    'software': {
        'software_inventory': 'Refresh Software Inventory',
        'install_app': 'Install Application (WinGet)',
        'uninstall_app': 'Uninstall Application'
    },
    'security': {
        'security_scan': 'Refresh Security Status',
        'notify_client': 'Send User Notification'
    },
    'network': {
        'network_report': 'Refresh Network Inventory',
        'connectivity_test': 'Run Connectivity Test'
    },
    'usage': {
        'stop_application': 'Stop Running Process',
        'app_block': 'Block Application (AppLocker)',
        'app_unblock': 'Unblock Application (AppLocker)'
    },
    'operations': {
        'restart_endpoint': 'Restart Endpoint',
        'shutdown_endpoint': 'Shut Down Endpoint',
        'cancel_shutdown': 'Cancel Pending Shutdown'
    }
}
ALL_ACTIONS = {k: v for cat in ACTIONS.values() for k, v in cat.items()}

def get_settings():
    defaults = {
        'monitoring_interval_seconds': '30',
        'cpu_warn': '80', 'cpu_critical': '95',
        'ram_warn': '85', 'ram_critical': '95',
        'disk_warn': '85', 'disk_critical': '95',
        'bandwidth_capacity_mbps': '0',
        'bandwidth_warn': '80', 'bandwidth_critical': '95'
    }
    for item in AppSetting.objects.all():
        defaults[item.key] = item.value
    return defaults

def setting_float(key, env_key, default):
    try:
        return float(get_settings().get(key, os.environ.get(env_key, str(default))))
    except (TypeError, ValueError):
        return float(default)

def audit_log(actor, cat, action, target, detail):
    AuditLog.objects.create(
        actor=actor, category=cat, action=action, target=target, detail=str(detail)[:3000]
    )

def is_authorized(request):
    return request.headers.get('X-API-Key', '') == API_KEY

def condition_sustained(agent_id, metric, active, min_samples=2, min_seconds=25):
    now = dj_timezone.now()
    if not active:
        AlertCondition.objects.filter(agent_id=agent_id, metric=metric).delete()
        return False

    cond, created = AlertCondition.objects.get_or_create(
        agent_id=agent_id, metric=metric,
        defaults={'started_at': now, 'last_seen': now, 'samples': 1}
    )
    if created:
        return False

    elapsed = (now - cond.started_at).total_seconds()
    cond.samples += 1
    cond.last_seen = now
    cond.save(update_fields=['samples', 'last_seen'])
    return cond.samples >= min_samples and elapsed >= min_seconds

def create_alert(agent_id, severity, title, detail):
    existing = Alert.objects.filter(agent_id=agent_id, title=title, status='Open').order_by('-id').first()
    if existing:
        existing.ts = dj_timezone.now()
        existing.severity = severity
        existing.detail = detail
        existing.save(update_fields=['ts', 'severity', 'detail'])
    else:
        Alert.objects.create(
            agent_id=agent_id, severity=severity, title=title, detail=detail, status='Open'
        )

def resolve_alert(agent_id, title, reason='Kondisi kembali normal oleh telemetri terbaru'):
    Alert.objects.filter(agent_id=agent_id, title=title, status='Open').update(
        status='Resolved'
    )

def format_result(value):
    if not value:
        return 'Menunggu respons dari agent...'
    try:
        obj = json.loads(value) if isinstance(value, str) else value
        inv = obj.get('result', obj).get('inventory') if isinstance(obj, dict) else None
        if isinstance(inv, dict):
            sw = inv.get('software') or []
            net = inv.get('network') or []
            sec = inv.get('security') or {}
            fg = inv.get('foreground_app') or {}
            lines = [
                'Penyegaran inventaris selesai.',
                f"Hostname: {inv.get('hostname','Unknown')}",
                f"Sistem Operasi: {inv.get('os_name','Unavailable')}",
                f"Penggunaan CPU: {inv.get('cpu_percent','Unavailable')}%",
                f"Penggunaan RAM: {inv.get('ram_percent','Unavailable')}%",
                f"Aplikasi Terpasang: {len(sw)} item",
                f"Interface Jaringan: {len(net)}",
                f"Firewall: {str(sec.get('firewall','Unavailable'))[:180]}",
                f"Aplikasi Depan (Foreground): {fg.get('process','Unavailable')}"
            ]
            return '\n'.join(lines)
        if isinstance(obj, dict) and 'error' in obj:
            return 'GAGAL: ' + str(obj.get('error'))
        return json.dumps(obj, ensure_ascii=False, indent=2)
    except Exception:
        return str(value)

def firewall_profile_html(value):
    import ast
    profiles = []
    if isinstance(value, str):
        raw = value.strip()
        if not raw or raw.lower() in ('unavailable', 'unknown', 'none', 'null'):
            return '<span class="text-secondary small">Status firewall tidak tersedia</span>'
        try:
            value = json.loads(raw)
        except Exception:
            try:
                value = ast.literal_eval(raw)
            except Exception:
                return f'<span class="badge bg-secondary-lt">{html.escape(raw)}</span>'
    if isinstance(value, dict):
        if isinstance(value.get('profiles'), (list, dict)):
            value = value['profiles']
        else:
            value = [{'Name': k, 'Enabled': v} for k, v in value.items()]
    if isinstance(value, list):
        profiles = value
    elif value in ('enabled', 'disabled', 'check_required'):
        cls = 'bg-success-lt text-success' if value == 'enabled' else 'bg-danger-lt text-danger'
        return f'<span class="badge {cls}">{html.escape(str(value).title())}</span>'
    else:
        return '<span class="text-secondary small">Status firewall tidak tersedia</span>'

    rows = []
    for item in profiles:
        if not isinstance(item, dict):
            continue
        name = item.get('Name', item.get('name', item.get('profile', 'Unknown')))
        enabled = item.get('Enabled', item.get('enabled', item.get('status')))
        if isinstance(enabled, bool):
            state = 'Enabled' if enabled else 'Disabled'
        elif str(enabled).strip().lower() in ('1', 'true', 'yes', 'enabled', 'on'):
            state = 'Enabled'
        elif str(enabled).strip().lower() in ('0', 'false', 'no', 'disabled', 'off'):
            state = 'Disabled'
        else:
            state = 'Unknown'
        cls = 'bg-success-lt text-success' if state == 'Enabled' else ('bg-danger-lt text-danger' if state == 'Disabled' else 'bg-warning-lt text-warning')
        rows.append(f'<div class="d-flex justify-content-between align-items-center py-2 border-bottom"><span><b>{html.escape(str(name))} Profile</b></span><span class="badge {cls}">{state}</span></div>')
    return ''.join(rows) if rows else '<span class="text-secondary small">Detail profil firewall tidak tersedia</span>'

def alert_destination(a):
    title = a.title if hasattr(a, 'title') else a.get('title', '')
    detail = a.detail if hasattr(a, 'detail') else a.get('detail', '')
    text = (str(title) + ' ' + str(detail)).lower()
    if any(k in text for k in ('disk', 'capacity')):
        return 'hardware'
    if any(k in text for k in ('memory', 'ram', 'cpu')):
        return 'hardware'
    if any(k in text for k in ('bandwidth', 'network', 'connectivity')):
        return 'network'
    if any(k in text for k in ('antivirus', 'firewall', 'security', 'malware')):
        return 'security'
    return 'overview'

def alert_open_href(a):
    agent_id = a.agent_id if hasattr(a, 'agent_id') else a.get('agent_id')
    tab = alert_destination(a)
    return f"/endpoint/{agent_id}/?tab={tab}"

def get_processed_endpoints():
    endpoints = list(Endpoint.objects.all())
    alerts = list(Alert.objects.filter(status='Open'))
    now = dj_timezone.now()

    for e in endpoints:
        age = (now - e.last_seen).total_seconds()
        e.status = 'Online' if age <= 90 else ('Stale' if age <= 180 else 'Offline')
        e.open_alerts = [a for a in alerts if a.agent_id == e.agent_id]

        if any(a.severity in ('Critical', 'High') for a in e.open_alerts):
            e.health = 'Critical'
        elif e.open_alerts or e.status == 'Stale':
            e.health = 'Warning'
        elif e.status == 'Offline':
            e.health = 'Offline'
        else:
            e.health = 'Healthy'

        # Formatted dates
        od = e.raw().get('os_detail', {}) or {}
        e.os_install_display = od.get('InstallDate') or 'Unavailable'
        sec = e.security()
        e.signature_display = sec.get('antivirus_signature_last_updated') or 'Unavailable'
        e.quickscan_display = sec.get('antivirus_last_quick_scan') or 'Unavailable'

        software_list = e.software()
        for sw in software_list:
            sw['install_date_display'] = sw.get('install_date') or 'Not provided'
        e.processed_software = software_list

    return endpoints

# Django Context Processor
def inject_globals(request):
    open_alerts_count = Alert.objects.filter(status='Open').count()
    return {
        'alert_open_href': alert_open_href,
        'format_result': format_result,
        'all_actions': ALL_ACTIONS,
        'open_alerts_count': open_alerts_count
    }

# --- VIEWS ---

def index(request):
    return redirect('/page/dashboard/')

def health(request):
    return JsonResponse({'status': 'ok', 'app': 'IT Operation Control Tower (Django + Tabler.io Edition)'})

@csrf_exempt
def heartbeat(request):
    if request.method != 'POST':
        return HttpResponseBadRequest('POST required')
    if not is_authorized(request):
        return JsonResponse({'error': 'unauthorized'}, status=401)

    try:
        p = json.loads(request.body.decode('utf-8'))
    except Exception:
        return JsonResponse({'error': 'invalid json'}, status=400)

    aid = p.get('agent_id')
    if not aid:
        return JsonResponse({'error': 'agent_id required'}, status=400)

    now = dj_timezone.now()
    endpoint, _ = Endpoint.objects.update_or_create(
        agent_id=aid,
        defaults={
            'hostname': p.get('hostname'),
            'os_name': p.get('os_name'),
            'os_version': p.get('os_version'),
            'os_release': p.get('os_release'),
            'architecture': p.get('architecture'),
            'manufacturer': p.get('manufacturer'),
            'model': p.get('model'),
            'serial_number': p.get('serial_number'),
            'cpu': p.get('cpu'),
            'cpu_cores': p.get('cpu_cores'),
            'cpu_percent': p.get('cpu_percent') or 0.0,
            'ram_total_gb': p.get('ram_total_gb') or 0.0,
            'ram_used_gb': p.get('ram_used_gb') or 0.0,
            'ram_percent': p.get('ram_percent') or 0.0,
            'disk_json': json.dumps(p.get('disks', [])),
            'network_json': json.dumps(p.get('network', [])),
            'software_json': json.dumps(p.get('software', [])),
            'security_json': json.dumps(p.get('security', {})),
            'status': 'Online',
            'last_seen': now,
            'raw_json': json.dumps(p)
        }
    )

    # Track foreground app
    fg = p.get('foreground_app') or {}
    proc_name = str(fg.get('process') or '')[:260]
    user_name = str(fg.get('user_name') or p.get('user_name') or 'Unknown')[:160]
    locked = bool(fg.get('session_locked')) or proc_name.lower() == 'lockapp.exe'

    if proc_name and not locked:
        prev = AppUsage.objects.filter(agent_id=aid).order_by('-id').first()
        delta = 0
        if prev and prev.process == proc_name and (prev.user_name or 'Unknown') == user_name:
            elapsed = (now - prev.ts).total_seconds()
            if 0 < elapsed <= 90:
                delta = int(elapsed)

        AppUsage.objects.create(
            agent_id=aid, process=proc_name, window_title=str(fg.get('window_title', ''))[:500],
            active_seconds=int(fg.get('active_seconds') or 0), user_name=user_name, ts=now
        )
        if delta:
            day = now.date()
            tot, _ = AppUsageTotal.objects.get_or_create(
                day=day, agent_id=aid, user_name=user_name, process=proc_name,
                defaults={'active_seconds': 0}
            )
            tot.active_seconds += delta
            tot.save(update_fields=['active_seconds'])

    # Evaluate Threshold Alerts
    cpu = float(p.get('cpu_percent') or 0)
    ram = float(p.get('ram_percent') or 0)
    cpu_warn = setting_float('cpu_warn', 'ITOPS_CPU_WARN', 80)
    cpu_crit = setting_float('cpu_critical', 'ITOPS_CPU_CRITICAL', 95)
    ram_warn = setting_float('ram_warn', 'ITOPS_RAM_WARN', 85)
    ram_crit = setting_float('ram_critical', 'ITOPS_RAM_CRITICAL', 95)

    cpu_sustained = condition_sustained(aid, 'cpu', cpu >= cpu_warn)
    if cpu >= cpu_crit and cpu_sustained:
        create_alert(aid, 'Critical', 'CPU utilization critical',
                     f'CPU {cpu:.1f}% (ambang batas {cpu_crit:.0f}%). Periksa proses beban tinggi.')
    elif cpu >= cpu_warn and cpu_sustained:
        create_alert(aid, 'Medium', 'CPU utilization high',
                     f'CPU {cpu:.1f}% (ambang batas {cpu_warn:.0f}%).')
    elif cpu < cpu_warn:
        resolve_alert(aid, 'CPU utilization critical')
        resolve_alert(aid, 'CPU utilization high')

    ram_sustained = condition_sustained(aid, 'ram', ram >= ram_warn)
    if ram >= ram_crit and ram_sustained:
        create_alert(aid, 'Critical', 'Memory utilization critical',
                     f'RAM {ram:.1f}% (ambang batas {ram_crit:.0f}%). Tinjau proses pemakaian memori tinggi.')
    elif ram >= ram_warn and ram_sustained:
        create_alert(aid, 'Medium', 'Memory utilization high',
                     f'RAM {ram:.1f}% (ambang batas {ram_warn:.0f}%).')
    elif ram < ram_warn:
        resolve_alert(aid, 'Memory utilization critical')
        resolve_alert(aid, 'Memory utilization high')

    # Disk Capacity Alerts
    disk_warn = setting_float('disk_warn', 'ITOPS_DISK_WARN', 85)
    disk_crit = setting_float('disk_critical', 'ITOPS_DISK_CRITICAL', 95)
    any_disk_warn = False
    for d in p.get('disks', []):
        used = float(d.get('percent_used') or 0)
        mount = d.get('mount') or 'Disk'
        if used >= disk_warn:
            any_disk_warn = True
        if used >= disk_crit:
            create_alert(aid, 'Critical', 'Disk capacity critical',
                         f'{mount}: {used:.1f}% terpakai (ambang batas {disk_crit:.0f}%).')
        elif used >= disk_warn:
            create_alert(aid, 'Medium', 'Disk capacity warning',
                         f'{mount}: {used:.1f}% terpakai (ambang batas {disk_warn:.0f}%).')
    if p.get('disks') and not any_disk_warn:
        resolve_alert(aid, 'Disk capacity critical')
        resolve_alert(aid, 'Disk capacity warning')

    # Bandwidth Alerts
    cap = setting_float('bandwidth_capacity_mbps', 'ITOPS_LINK_CAPACITY_MBPS', 0)
    if cap > 0:
        for rate in p.get('network_throughput', []) or []:
            down = float(rate.get('download_mbps') or 0)
            up = float(rate.get('upload_mbps') or 0)
            pct = max(down, up) / cap * 100
            bw_warn = setting_float('bandwidth_warn', 'ITOPS_BW_WARN', 80)
            bw_crit = setting_float('bandwidth_critical', 'ITOPS_BW_CRITICAL', 95)
            bw_sustained = condition_sustained(aid, 'bandwidth:' + str(rate.get('interface', 'unknown')), pct >= bw_warn)
            if pct >= bw_crit and bw_sustained:
                create_alert(aid, 'High', 'Network bandwidth critical',
                             f"{rate.get('interface','Unknown')}: {max(down,up):.2f} Mbps ({pct:.1f}% dari kapasitas {cap:g} Mbps).")
            elif pct >= bw_warn and bw_sustained:
                create_alert(aid, 'Medium', 'Network bandwidth high',
                             f"{rate.get('interface','Unknown')}: {max(down,up):.2f} Mbps ({pct:.1f}% dari kapasitas {cap:g} Mbps).")

    audit_log(p.get('hostname', 'agent'), 'system', 'HEARTBEAT', aid, 'Telemetri inventaris diperbarui')
    interval = int(setting_float('monitoring_interval_seconds', 'ITOPS_MONITORING_INTERVAL_SECONDS', 30))
    return JsonResponse({'status': 'accepted', 'last_seen': now.isoformat(), 'monitoring_interval_seconds': interval})

def catalog_search(request):
    q = request.GET.get('q', '').strip()[:100]
    if len(q) < 2:
        return JsonResponse({'items': [], 'message': 'Masukkan minimal 2 karakter.'})
    exe = shutil.which('winget')
    if not exe:
        return JsonResponse({'items': [], 'message': 'WinGet tidak terpasang di host dashboard.'})
    try:
        p = subprocess.run([exe, 'search', q, '--accept-source-agreements', '--disable-interactivity'],
                           capture_output=True, text=True, timeout=25, encoding='utf-8', errors='replace')
        lines = (p.stdout or '').splitlines()
        items = []
        start = next((i for i, x in enumerate(lines) if re.search(r'Name\s+Id\s+Version', x)), None)
        if start is not None:
            for line in lines[start + 2:]:
                if not line.strip() or set(line.strip()) <= set('- '):
                    continue
                cols = re.split(r'\s{2,}', line.strip())
                if len(cols) >= 3 and re.fullmatch(r'[A-Za-z0-9._+-]{2,160}', cols[1]):
                    items.append({'name': cols[0], 'id': cols[1], 'version': cols[2], 'source': cols[3] if len(cols) > 3 else 'winget'})
                if len(items) >= 40:
                    break
        return JsonResponse({'items': items, 'message': '' if items else 'Tidak ada paket aplikasi yang cocok.'})
    except Exception as e:
        return JsonResponse({'items': [], 'message': 'Pencarian katalog gagal: ' + str(e)[:300]}, status=500)

@csrf_exempt
def next_job(request):
    if not is_authorized(request):
        return JsonResponse({'error': 'unauthorized'}, status=401)
    aid = request.GET.get('agent_id', '')
    j = Job.objects.filter(agent_id=aid, status='Queued').order_by('id').first()
    if not j:
        return JsonResponse({'job': None})
    j.status = 'Running'
    j.save(update_fields=['status'])
    return JsonResponse({'job': {'id': j.id, 'action': j.action, 'params': json.loads(j.params or '{}')}})

@csrf_exempt
def store_job_result(request, jid):
    if request.method != 'POST':
        return HttpResponseBadRequest('POST required')
    if not is_authorized(request):
        return JsonResponse({'error': 'unauthorized'}, status=401)
    try:
        p = json.loads(request.body.decode('utf-8'))
    except Exception:
        p = {}

    j = Job.objects.filter(id=jid).first()
    if not j:
        return JsonResponse({'error': 'not_found'}, status=404)

    status = 'Completed' if p.get('ok') else 'Failed'
    val = p.get('result', '')
    if isinstance(val, (dict, list)):
        val = json.dumps(val, ensure_ascii=False)

    j.status = status
    j.result = str(val)[:30000]
    j.completed_at = dj_timezone.now()
    j.save(update_fields=['status', 'result', 'completed_at'])

    audit_log('agent', j.category, j.action, j.agent_id, f"{status}: {str(val)[:1200]}")
    return JsonResponse({'status': 'stored'})

@csrf_exempt
def refresh_all_monitoring(request):
    if request.method == 'POST':
        actions = [('hardware', 'refresh_inventory'), ('software', 'software_inventory'),
                   ('network', 'network_report'), ('security', 'security_scan')]
        endpoints = Endpoint.objects.all()
        for ep in endpoints:
            for cat, act in actions:
                Job.objects.create(agent_id=ep.agent_id, category=cat, action=act, params='{}', status='Queued')
        audit_log('dashboard', 'monitoring', 'REFRESH_ALL_MONITORING', f'{endpoints.count()} endpoints', 'Refresh queued')
    return redirect('/page/dashboard/?refresh_queued=1')

@csrf_exempt
def handle_action(request):
    if request.method != 'POST':
        return HttpResponseBadRequest('POST required')
    aid = request.POST.get('agent_id', '')
    act = request.POST.get('action', '')
    params = {}

    actual_category = next((cat for cat, items in ACTIONS.items() if act in items), None)
    if actual_category is None:
        return HttpResponseBadRequest('Aksi tidak terdaftar.')

    if act in ('install_app', 'uninstall_app'):
        pkg = request.POST.get('package_id', '').strip()
        if act == 'install_app':
            if not re.fullmatch(r'[A-Za-z0-9._+-]{2,160}', pkg):
                return HttpResponseBadRequest('Pilih paket aplikasi WinGet yang valid.')
            params['package_id'] = pkg
            params['package_name'] = request.POST.get('package_name', '').strip()[:200]
        else:
            if not pkg or len(pkg) > 260:
                return HttpResponseBadRequest('Pilih aplikasi dari inventaris yang valid.')
            params['package_id'] = pkg

    if act in ('stop_application', 'app_block', 'app_unblock'):
        appname = request.POST.get('app_name', '').strip()
        if not re.fullmatch(r'[A-Za-z0-9._ -]{1,120}', appname) or appname in ('.', '..'):
            return HttpResponseBadRequest('Nama executable tidak valid (contoh: notepad.exe).')
        params['app_name'] = appname

    if act == 'notify_client':
        msg = request.POST.get('message', '').strip()
        if not msg or len(msg) > 500:
            return HttpResponseBadRequest('Pesan notifikasi harus 1-500 karakter.')
        params['message'] = msg

    if not Endpoint.objects.filter(agent_id=aid).exists():
        return HttpResponseNotFound('Endpoint tidak ditemukan')

    Job.objects.create(agent_id=aid, category=actual_category, action=act, params=json.dumps(params), status='Queued')
    audit_log('dashboard', actual_category, act, aid, params)
    return redirect(f'/endpoint/{aid}/?tab=overview')

@csrf_exempt
def acknowledge_alert(request, aid):
    Alert.objects.filter(id=aid).update(status='Acknowledged')
    return redirect('/page/alerts/')

@csrf_exempt
def save_settings(request):
    if request.method == 'POST':
        keys = {
            'monitoring_interval_seconds': (15, 3600),
            'cpu_warn': (1, 99), 'cpu_critical': (2, 100),
            'ram_warn': (1, 99), 'ram_critical': (2, 100),
            'disk_warn': (1, 99), 'disk_critical': (2, 100),
            'bandwidth_capacity_mbps': (0, 10000000),
            'bandwidth_warn': (1, 99), 'bandwidth_critical': (2, 100)
        }
        values = {}
        for key, (lo, hi) in keys.items():
            try:
                val = float(request.POST.get(key, ''))
            except (TypeError, ValueError):
                return HttpResponseBadRequest(f'Nilai numerik tidak valid untuk {key}.')
            if not lo <= val <= hi:
                return HttpResponseBadRequest(f'{key} harus di antara {lo} dan {hi}.')
            values[key] = str(int(val) if key == 'monitoring_interval_seconds' else val)

        for k, v in values.items():
            AppSetting.objects.update_or_create(key=k, defaults={'value': v})
        audit_log('dashboard', 'settings', 'UPDATE_GLOBAL_SETTINGS', 'all-endpoints', values)
    return redirect('/page/settings/?saved=1')

# --- PAGE RENDERING ---

def view_page(request, page):
    allowed_pages = {
        'dashboard', 'endpoints', 'hardware', 'software', 'network',
        'security', 'usage', 'remote', 'alerts', 'actions', 'reports', 'settings'
    }
    if page not in allowed_pages:
        return HttpResponseNotFound('Halaman tidak ditemukan')

    eps = get_processed_endpoints()
    jobs = list(Job.objects.all()[:100])
    logs = list(AuditLog.objects.all()[:100])
    alerts = list(Alert.objects.all()[:100])
    open_alerts = [a for a in alerts if a.status == 'Open']

    critical_count = sum(1 for e in eps if e.health == 'Critical')
    warning_count = sum(1 for e in eps if e.health == 'Warning')
    offline_count = sum(1 for e in eps if e.status == 'Offline')
    online_count = sum(1 for e in eps if e.status == 'Online')
    pending_jobs_count = Job.objects.filter(status__in=['Queued', 'Running']).count()

    context = {
        'page': page,
        'eps': eps,
        'jobs': jobs,
        'logs': logs,
        'alerts': alerts,
        'open_alerts': open_alerts,
        'critical_count': critical_count,
        'warning_count': warning_count,
        'offline_count': offline_count,
        'online_count': online_count,
        'pending_jobs_count': pending_jobs_count,
        'attention_list': [e for e in eps if e.health != 'Healthy'],
        'cfg': get_settings(),
    }

    if page == 'remote':
        remote_url = os.environ.get('MESH_CENTRAL_URL', '').strip().rstrip('/')
        valid_remote = remote_url.startswith('https://') or (remote_url.startswith('http://') and os.environ.get('MESH_CENTRAL_ALLOW_HTTP', '0') == '1')
        context['remote_url'] = remote_url
        context['valid_remote'] = valid_remote

    template_map = {
        'dashboard': 'dashboard.html',
        'endpoints': 'endpoints.html',
        'hardware': 'hardware.html',
        'software': 'software.html',
        'network': 'network.html',
        'security': 'security.html',
        'usage': 'usage.html',
        'remote': 'remote.html',
        'alerts': 'alerts.html',
        'actions': 'actions.html',
        'reports': 'reports.html',
        'settings': 'settings.html'
    }
    return render(request, template_map[page], context)

def endpoint_detail(request, agent_id):
    eps = get_processed_endpoints()
    e = next((x for x in eps if x.agent_id == agent_id), None)
    if not e:
        return HttpResponseNotFound('Endpoint tidak ditemukan')

    tab = request.GET.get('tab', 'overview')
    endpoint_logs = list(AuditLog.objects.filter(target=agent_id) | AuditLog.objects.filter(actor=e.hostname))[:50]
    firewall_html = firewall_profile_html(e.security().get('firewall'))
    mesh_url = os.environ.get('MESH_CENTRAL_URL', '').rstrip('/')

    return render(request, 'endpoint_detail.html', {
        'page': 'endpoints',
        'e': e,
        'active_tab': tab,
        'endpoint_logs': endpoint_logs,
        'firewall_html': firewall_html,
        'mesh_url': mesh_url
    })
