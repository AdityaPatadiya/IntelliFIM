from django.apps import AppConfig


class NtaConfig(AppConfig):
    default_auto_field = 'django.db.models.BigAutoField'
    name = 'NTA'
    verbose_name = "Network Monitoring"

    # def ready(self):
    #     import NTA.signals
