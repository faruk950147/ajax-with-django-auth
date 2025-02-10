from django import  forms
from tasks.models import Student

class StudentForm(forms.ModelForm):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        for field in self.fields:
            self.fields[field].widget.attrs.update({'class': 'form-control', 'cols': '6', 'rows': '4'})
            
    class Meta:
        model = Student
        fields = (
            '__all__'
        )
        widgets = {
            'name': forms.TextInput(attrs={
                'id': 'name'
            }),
            'department': forms.TextInput(attrs={
            'id': 'department'
            }),
            'phone': forms.TextInput(attrs={
            'id': 'phone'
            }),
        }
        