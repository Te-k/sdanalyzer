#!/usr/bin/env python3
import os
import datetime
from flask import Flask, render_template, request, redirect, url_for, send_file, jsonify
from peewee import Model, CharField, ForeignKeyField, DateTimeField, TextField, BooleanField, IntegerField
from playhouse.sqlite_ext import SqliteExtDatabase, JSONField
from .forms import PhoneForm
from .utils import get_db_path, SUSPICIOUS_PERMISSIONS

app = Flask(__name__)
app.config['SECRET_KEY'] = os.urandom(24)
db = SqliteExtDatabase(get_db_path())

# Models
class Phone(Model):
    name = CharField()
    model = CharField(null=True)
    created_on = DateTimeField(default=datetime.datetime.now)
    class Meta:
        database = db

class Apk(Model):
    owner = ForeignKeyField(Phone, backref='apks')
    path = CharField()
    md5 = CharField()
    sha1 = CharField()
    sha256 = CharField()
    package_name = CharField()
    app_name = CharField()
    manifest = TextField()
    certificate_sha1 = CharField(null = True)
    certificate = JSONField(null = True)
    permissions = JSONField(null = True)
    permissions_suspicious = IntegerField(null=True)
    urls = JSONField(null = True)
    strings = JSONField(null = True)
    size = IntegerField()
    koodous_link = CharField(null = True)
    vt_positives = IntegerField(null=True)
    vt_total = IntegerField(null = True)
    vt_link = CharField(null = True)
    suspicious = BooleanField(null=True)
    suspicious_level = IntegerField()

    class Meta:
        database = db


db.connect()
db.create_tables([Phone, Apk])


#----------------------------------- Views ------------------------------------
@app.route('/')
def hello():
    phones = Phone.select()
    return render_template('index.html', phones=phones)


@app.route('/phones/new', methods=['GET', 'POST'])
def phones_new():
    form = PhoneForm()
    if form.validate_on_submit():
        new_phone = Phone.create(name=form.name.data, model=form.model.data)
        return redirect('/phones/{}'.format(new_phone.id))
    return render_template('phones_new.html', form=form)


@app.route('/phones/<int:_id>')
def phones_show(_id):
    phone = Phone.get(Phone.id == _id)
    apks = Apk.select().join(Phone).where(Phone.id == _id)
    return render_template('phones_show.html', phone=phone, apks=apks)


@app.route('/apk/<int:_id>')
def apk_show(_id):
    apk = Apk.get(Apk.id == _id)
    phone = apk.owner
    return render_template('apk_show.html', phone=phone, apk=apk, sp=SUSPICIOUS_PERMISSIONS)

@app.route('/apk/<int:_id>/status')
def apk_status(_id):
    apk = Apk.get(Apk.id == _id)
    status = request.args.get('status')
    if status == 'good':
        apk.suspicious = False
    elif status == 'bad':
        apk.suspicious = True
    else:
        apk.suspicious = None
    apk.save()
    redir = request.args.get('next')
    if redir is not None:
        if redir == 'phone':
            phone = apk.owner
            return redirect('/phones/{}'.format(phone.id))
        elif redir == 'json':
            return 'All good'
    return redirect('/apk/{}'.format(apk.id))


@app.route('/apk/bulk_status', methods=['POST'])
def apk_bulk_status():
    status = request.json['status']
    apks = request.json['apks']
    if apks and status:
        if status == 'good':
            s = False
        elif status == 'bad':
            s = true
        else:
            s = None

        for p in apks:
            apk = Apk.get(Apk.id == int(p))
            if apk.suspicious != s:
                apk.suspicious = s
                apk.save()
        return jsonify({'result': 'good'})
    else:
        return "Record not found", 400
