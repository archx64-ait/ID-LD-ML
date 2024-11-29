import os
import pickle
import warnings
from typing import Any

import pandas as pd
from django.shortcuts import redirect
from django.urls import reverse_lazy
from django.views.generic import TemplateView
from django.views.generic.edit import FormView

from IntrusionDetection.settings import PROJECT_ROOT
from predictor.forms import DetectionForm

warnings.filterwarnings("ignore")


class IndexView(TemplateView):
    template_name = "index.html"


class SuccessView(TemplateView):
    template_name = "success.html"

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)

        result = self.request.GET.get("result")

        try:
            # Add the result to the context
            context["result"] = str(result)

        except ValueError:
            context["result"] = 'Benign'

        return context


class PredictFormView(FormView):
    template_name = "predict.html"
    success_url = reverse_lazy("predictor:success")
    form_class = DetectionForm
    model_path = os.path.join(PROJECT_ROOT, "best_model.pkl")
    loaded_model = pickle.load(open(model_path, "rb"))
    columns = ['Bwd Packet Length Std', 'Bwd Packet Length Max', 'Packet Length Std', 'Packet Length Variance',
               'Bwd Packet Length Mean', 'Avg Bwd Segment Size', 'Packet Length Max', 'Avg Packet Size',
               'Init Fwd Win Bytes', 'Packet Length Mean', 'Idle Std']

    def predict(self, data_to_predict):
        data_to_predict_df = pd.DataFrame(data_to_predict, columns=self.columns)
        predicted_class = 'Benign'
        if self.loaded_model.predict(data_to_predict_df) == 0:
            predicted_class = 'Benign'
        elif self.loaded_model.predict(data_to_predict_df) == 1:
            predicted_class = 'Botnet'
        elif self.loaded_model.predict(data_to_predict_df) == 2:
            predicted_class = 'Bruteforce'
        elif self.loaded_model.predict(data_to_predict_df) == 3:
            predicted_class = 'DDoS'
        elif self.loaded_model.predict(data_to_predict_df) == 0:
            predicted_class = 'Benign'
        return predicted_class

    def form_valid(self, form):
        backward_packet_length_std = form.cleaned_data["backward_packet_length_std"]
        backward_packet_length_max = form.cleaned_data["backward_packet_length_max"]
        packet_length_std = form.cleaned_data["packet_length_std"]
        packet_length_variance = form.cleaned_data["packet_length_variance"]
        backward_packet_length_mean = form.cleaned_data["backward_packet_length_mean"]
        average_backward_segment = form.cleaned_data["average_backward_segment"]
        packet_length_max = form.cleaned_data["packet_length_max"]
        average_packet_size = form.cleaned_data["average_packet_size"]
        initial_forward_windows_bytes = form.cleaned_data["initial_forward_windows_bytes"]
        packet_length_mean = form.cleaned_data["packet_length_mean"]
        idle_std = form.cleaned_data["idle_std"]

        data_to_predict = [
            [backward_packet_length_std, backward_packet_length_max, packet_length_std, packet_length_variance,
                backward_packet_length_mean, average_backward_segment, packet_length_max, average_packet_size,
                initial_forward_windows_bytes, packet_length_mean, idle_std, ]]

        result = self.predict(data_to_predict)
        return redirect(f"{reverse_lazy('predictor:success')}?result={result}")

    def get_context_data(self, **kwargs: Any) -> dict[str, Any]:
        context = super().get_context_data(**kwargs)
        context["results"] = getattr(self, "result", None)
        return context

    def form_invalid(self, form):
        return super().form_invalid(form)
