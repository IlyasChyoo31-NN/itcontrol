from django.contrib import admin
from .models import Endpoint, Job, AuditLog, Alert, AppSetting, AppUsage

@admin.register(Endpoint)
class EndpointAdmin(admin.ModelAdmin):
    list_display = ('hostname', 'agent_id', 'status', 'cpu_percent', 'ram_percent', 'last_seen')
    search_fields = ('hostname', 'agent_id', 'serial_number', 'model')
    list_filter = ('status', 'os_name')

@admin.register(Job)
class JobAdmin(admin.ModelAdmin):
    list_display = ('id', 'agent_id', 'category', 'action', 'status', 'created_at', 'completed_at')
    list_filter = ('status', 'category')
    search_fields = ('agent_id', 'action')

@admin.register(AuditLog)
class AuditLogAdmin(admin.ModelAdmin):
    list_display = ('ts', 'actor', 'category', 'action', 'target')
    list_filter = ('category', 'actor')
    search_fields = ('actor', 'target', 'detail')

@admin.register(Alert)
class AlertAdmin(admin.ModelAdmin):
    list_display = ('severity', 'title', 'agent_id', 'status', 'ts')
    list_filter = ('severity', 'status')
    search_fields = ('title', 'detail', 'agent_id')

@admin.register(AppSetting)
class AppSettingAdmin(admin.ModelAdmin):
    list_display = ('key', 'value')
    search_fields = ('key',)

@admin.register(AppUsage)
class AppUsageAdmin(admin.ModelAdmin):
    list_display = ('ts', 'agent_id', 'process', 'active_seconds', 'user_name')
    search_fields = ('agent_id', 'process', 'window_title')
