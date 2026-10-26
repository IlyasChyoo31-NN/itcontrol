from django.db import models
from django.utils import timezone
import json

class Endpoint(models.Model):
    agent_id = models.CharField(max_length=120, primary_key=True, verbose_name="Agent ID")
    hostname = models.CharField(max_length=200, null=True, blank=True)
    os_name = models.CharField(max_length=150, null=True, blank=True, verbose_name="OS")
    os_version = models.CharField(max_length=100, null=True, blank=True)
    os_release = models.CharField(max_length=100, null=True, blank=True)
    architecture = models.CharField(max_length=50, null=True, blank=True)
    manufacturer = models.CharField(max_length=150, null=True, blank=True)
    model = models.CharField(max_length=150, null=True, blank=True)
    serial_number = models.CharField(max_length=150, null=True, blank=True)
    cpu = models.CharField(max_length=200, null=True, blank=True)
    cpu_cores = models.IntegerField(null=True, blank=True)
    cpu_percent = models.FloatField(default=0.0)
    ram_total_gb = models.FloatField(default=0.0)
    ram_used_gb = models.FloatField(default=0.0)
    ram_percent = models.FloatField(default=0.0)
    disk_json = models.TextField(default='[]')
    network_json = models.TextField(default='[]')
    software_json = models.TextField(default='[]')
    security_json = models.TextField(default='{}')
    status = models.CharField(max_length=50, default='Online')
    last_seen = models.DateTimeField(default=timezone.now)
    raw_json = models.TextField(default='{}')

    class Meta:
        verbose_name = "Endpoint"
        verbose_name_plural = "Endpoints"
        ordering = ['hostname']

    def __str__(self):
        return f"{self.hostname or 'Unknown'} ({self.agent_id})"

    @property
    def disks_list(self):
        try:
            return json.loads(self.disk_json or '[]')
        except Exception:
            return []

    @property
    def network_list(self):
        try:
            items = json.loads(self.network_json or '[]')
            rates = {str(x.get('interface')): x for x in self.raw_data.get('network_throughput', [])}
            for item in items:
                r = rates.get(str(item.get('interface')), {})
                item['download_mbps'] = r.get('download_mbps')
                item['upload_mbps'] = r.get('upload_mbps')
            return items
        except Exception:
            return []

    @property
    def software_list(self):
        try:
            items = json.loads(self.software_json or '[]')
            for sw in items:
                if not sw.get('install_date_display'):
                    sw['install_date_display'] = sw.get('install_date') or 'Not provided'
            return items
        except Exception:
            return []

    @property
    def security_data(self):
        try:
            return json.loads(self.security_json or '{}')
        except Exception:
            return {}

    @property
    def raw_data(self):
        try:
            return json.loads(self.raw_json or '{}')
        except Exception:
            return {}

    @property
    def foreground_app(self):
        return self.raw_data.get('foreground_app', {})

    @property
    def processes_list(self):
        procdata = self.raw_data.get('running_processes', {})
        if isinstance(procdata, dict):
            return procdata.get('items', [])
        return []

    @property
    def total_download_mbps(self):
        rates = self.raw_data.get('network_throughput', [])
        vals = [r.get('download_mbps') for r in rates if isinstance(r.get('download_mbps'), (int, float))]
        return round(sum(vals), 2) if vals else None

    @property
    def total_upload_mbps(self):
        rates = self.raw_data.get('network_throughput', [])
        vals = [r.get('upload_mbps') for r in rates if isinstance(r.get('upload_mbps'), (int, float))]
        return round(sum(vals), 2) if vals else None

    def raw(self):
        return self.raw_data

    def security(self):
        return self.security_data

    def software(self):
        return self.software_list

    def disks(self):
        return self.disks_list

    def network(self):
        return self.network_list

class Job(models.Model):
    STATUS_CHOICES = [
        ('Queued', 'Queued'),
        ('Running', 'Running'),
        ('Completed', 'Completed'),
        ('Failed', 'Failed'),
    ]
    agent_id = models.CharField(max_length=120)
    category = models.CharField(max_length=60)
    action = models.CharField(max_length=100)
    params = models.TextField(default='{}')
    status = models.CharField(max_length=50, choices=STATUS_CHOICES, default='Queued')
    created_at = models.DateTimeField(default=timezone.now)
    result = models.TextField(null=True, blank=True)
    completed_at = models.DateTimeField(null=True, blank=True)

    class Meta:
        verbose_name = "Remote Job"
        verbose_name_plural = "Remote Jobs"
        ordering = ['-id']

    def __str__(self):
        return f"Job #{self.id} - {self.action} on {self.agent_id} [{self.status}]"

class AuditLog(models.Model):
    ts = models.DateTimeField(default=timezone.now)
    actor = models.CharField(max_length=100)
    category = models.CharField(max_length=60)
    action = models.CharField(max_length=100)
    target = models.CharField(max_length=200)
    detail = models.TextField(null=True, blank=True)

    class Meta:
        verbose_name = "Audit Log"
        verbose_name_plural = "Audit Logs"
        ordering = ['-id']

    def __str__(self):
        return f"[{self.ts}] {self.actor} - {self.action} on {self.target}"

class Alert(models.Model):
    SEVERITY_CHOICES = [
        ('Critical', 'Critical'),
        ('High', 'High'),
        ('Medium', 'Medium'),
        ('Low', 'Low'),
    ]
    STATUS_CHOICES = [
        ('Open', 'Open'),
        ('Acknowledged', 'Acknowledged'),
        ('Resolved', 'Resolved'),
    ]
    ts = models.DateTimeField(default=timezone.now)
    agent_id = models.CharField(max_length=120)
    severity = models.CharField(max_length=30, choices=SEVERITY_CHOICES, default='Medium')
    title = models.CharField(max_length=255)
    detail = models.TextField()
    status = models.CharField(max_length=30, choices=STATUS_CHOICES, default='Open')

    class Meta:
        verbose_name = "Alert"
        verbose_name_plural = "Alerts"
        ordering = ['-id']

    def __str__(self):
        return f"[{self.severity}] {self.title} on {self.agent_id} ({self.status})"

    @property
    def open_href(self):
        text = (str(self.title or '') + ' ' + str(self.detail or '')).lower()
        if any(k in text for k in ('disk', 'capacity')):
            tab = 'hardware'
        elif any(k in text for k in ('memory', 'ram', 'cpu')):
            tab = 'hardware'
        elif any(k in text for k in ('bandwidth', 'network', 'connectivity')):
            tab = 'network'
        elif any(k in text for k in ('antivirus', 'firewall', 'security', 'malware')):
            tab = 'security'
        else:
            tab = 'overview'
        return f"/endpoint/{self.agent_id}/?tab={tab}"

class AlertCondition(models.Model):
    agent_id = models.CharField(max_length=120)
    metric = models.CharField(max_length=120)
    started_at = models.DateTimeField(default=timezone.now)
    last_seen = models.DateTimeField(default=timezone.now)
    samples = models.IntegerField(default=1)

    class Meta:
        unique_together = ('agent_id', 'metric')

class AppSetting(models.Model):
    key = models.CharField(max_length=100, primary_key=True)
    value = models.TextField()

    class Meta:
        verbose_name = "App Setting"
        verbose_name_plural = "App Settings"

    def __str__(self):
        return f"{self.key}: {self.value}"

class AppUsage(models.Model):
    ts = models.DateTimeField(default=timezone.now)
    agent_id = models.CharField(max_length=120)
    process = models.CharField(max_length=260)
    window_title = models.CharField(max_length=500, null=True, blank=True)
    active_seconds = models.IntegerField(default=0)
    user_name = models.CharField(max_length=160, default='Unknown')

    class Meta:
        ordering = ['-id']

class AppUsageTotal(models.Model):
    day = models.DateField()
    agent_id = models.CharField(max_length=120)
    user_name = models.CharField(max_length=160, default='Unknown')
    process = models.CharField(max_length=260)
    active_seconds = models.IntegerField(default=0)

    class Meta:
        unique_together = ('day', 'agent_id', 'user_name', 'process')
