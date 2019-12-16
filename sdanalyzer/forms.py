from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, BooleanField, SubmitField
from wtforms.validators import DataRequired


class PhoneForm(FlaskForm):
    name = StringField('Name', validators=[DataRequired()])
    model = StringField('Model')
    submit = SubmitField('Create')
