from django.urls import path
from . import views

app_name = 'land_plots'

urlpatterns = [
    # Reference data endpoints
    path('categories/', views.LandCategoryListView.as_view(), name='land-categories'),
    path('purposes/', views.LandPurposeListView.as_view(), name='land-purposes'),
    path('regions/', views.RegionListView.as_view(), name='regions'),
    path('districts/', views.DistrictListView.as_view(), name='districts'),
    path('settlements/', views.SettlementListView.as_view(), name='settlements'),
    
    # Land plot endpoints
    path('plots/', views.LandPlotListView.as_view(), name='land-plots'),
    path('plots/search/', views.land_plot_search, name='land-plots-search'),
    path('plots/<uuid:pk>/', views.LandPlotDetailView.as_view(), name='land-plot-detail'),
    
    # Land plot owners
    path('plots/<uuid:land_plot_id>/owners/', views.LandPlotOwnerListView.as_view(), name='land-plot-owners'),
    
    # Land plot documents
    path('plots/<uuid:land_plot_id>/documents/', views.LandPlotDocumentListView.as_view(), name='land-plot-documents'),
]
