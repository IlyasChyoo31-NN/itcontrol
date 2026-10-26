from django.urls import path
from . import views

urlpatterns = [
    path('', views.index, name='index'),
    path('health/', views.health, name='health'),
    path('health', views.health),

    # Pages
    path('page/<str:page>/', views.view_page, name='view_page'),
    path('page/<str:page>', views.view_page),
    path('endpoint/<str:agent_id>/', views.endpoint_detail, name='endpoint_detail'),
    path('endpoint/<str:agent_id>', views.endpoint_detail),

    # Agent API endpoints (supports both with & without trailing slash)
    path('api/heartbeat', views.heartbeat, name='api_heartbeat'),
    path('api/heartbeat/', views.heartbeat),
    path('api/jobs/next', views.next_job, name='api_next_job'),
    path('api/jobs/next/', views.next_job),
    path('api/jobs/<int:jid>/result', views.store_job_result, name='api_job_result'),
    path('api/jobs/<int:jid>/result/', views.store_job_result),
    path('api/catalog/search', views.catalog_search, name='api_catalog_search'),
    path('api/catalog/search/', views.catalog_search),

    # Actions & Operations
    path('monitoring/refresh-all', views.refresh_all_monitoring, name='refresh_all_monitoring'),
    path('monitoring/refresh-all/', views.refresh_all_monitoring),
    path('action', views.handle_action, name='handle_action'),
    path('action/', views.handle_action),
    path('alert/<int:aid>/ack', views.acknowledge_alert, name='acknowledge_alert'),
    path('alert/<int:aid>/ack/', views.acknowledge_alert),
    path('settings/save', views.save_settings, name='save_settings'),
    path('settings/save/', views.save_settings),
]
