from django.urls import path, include
from rest_framework.routers import DefaultRouter
from . import views

app_name = 'land_plots'

router = DefaultRouter()
router.register(r'categories', views.LandCategoryListView, basename='land-categories')
router.register(r'purposes', views.LandPurposeListView, basename='land-purposes')
router.register(r'regions', views.RegionListView, basename='regions')
router.register(r'districts', views.DistrictListView, basename='districts')
router.register(r'settlements', views.SettlementListView, basename='settlements')

urlpatterns = [
    # Reference data endpoints
    path('', include(router.urls)),
    
    # Land plot endpoints
    path('plots/', views.LandPlotListView.as_view(), name='land-plots'),
    path('plots/search/', views.land_plot_search, name='land-plots-search'),
    path('plots/<uuid:pk>/', views.LandPlotDetailView.as_view(), name='land-plot-detail'),
    
    # Land plot owners
    path('plots/<uuid:land_plot_id>/owners/', views.LandPlotOwnerListView.as_view(), name='land-plot-owners'),
    
    # Land plot documents
    path('plots/<uuid:land_plot_id>/documents/', views.LandPlotDocumentListView.as_view(), name='land-plot-documents'),
]