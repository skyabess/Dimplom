from django.apps import AppConfig


class LandPlotsConfig(AppConfig):
    default_auto_field = 'django.db.models.BigAutoField'
    name = 'apps.land_plots'
    verbose_name = 'Land Plots'
    
    def ready(self):
        import apps.land_plots.signals