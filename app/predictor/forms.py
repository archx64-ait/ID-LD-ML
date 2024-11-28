from django import forms

class DetectionForm(forms.Form):
    average_packet_size = forms.FloatField(required=True, min_value=0, max_value=20000)
    average_backward_segment = forms.FloatField(required=True, min_value=0, max_value=35000)
    backward_packet_length_std = forms.FloatField(required=True, min_value=0, max_value=25000)
    backward_packet_length_max = forms.FloatField(required=True, min_value=0, max_value=70000)
    backward_packet_length_mean = forms.FloatField(required=True, min_value=0, max_value=35000)
    packet_length_std = forms.FloatField(required=True, min_value=0, max_value=25000)
    packet_length_max = forms.FloatField(required=True, min_value=0, max_value=70000)
    packet_length_mean = forms.FloatField(required=True, min_value=0, max_value=35000)
    packet_length_variance = forms.FloatField(required=True, min_value=0, max_value=520000000)
    initial_forward_windows_bytes = forms.FloatField(required=True, min_value=0, max_value=70000)
    idle_std = forms.FloatField(required=True, min_value=0, max_value=75000000)