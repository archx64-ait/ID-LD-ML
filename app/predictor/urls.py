from django.urls import path
from .views import PredictFormView, SuccessView

app_name = 'predictor'

urlpatterns = [
    path('detect/', PredictFormView.as_view(), name='detect'),
    path('success/', SuccessView.as_view(), name='success'),
]