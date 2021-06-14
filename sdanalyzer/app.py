#!/usr/bin/env python3
import os
import datetime
from flask import Flask, render_template, request, redirect, send_file, jsonify
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

    @classmethod
    def find_id_or_name(cls, id_or_name):
        """
        Find a phone by id or name
        """
        try:
            phone = Phone.get(Phone.id == int(id_or_name))
        except ValueError:
            phone = Phone.get(Phone.name == id_or_name)
        return phone


class Apk(Model):
    owner = ForeignKeyField(Phone, backref='apks')
    path = CharField()
    md5 = CharField()
    sha1 = CharField()
    sha256 = CharField()
    package_name = CharField()
    app_name = CharField()
    manifest = TextField()
    certificate_sha1 = CharField(null=True)
    certificate = JSONField(null=True)
    certificate_trusted = BooleanField()
    certificate_trusted_name = CharField(null=True)
    permissions = JSONField(null=True)
    permissions_suspicious = IntegerField(null=True)
    urls = JSONField(null=True)
    strings = JSONField(null=True)
    yara = JSONField(null=True)
    size = IntegerField()
    koodous_link = CharField(null=True)
    vt_positives = IntegerField(null=True)
    vt_total = IntegerField(null=True)
    vt_link = CharField(null=True)
    vt_check = BooleanField()
    frosting = BooleanField()
    suspicious = BooleanField(null=True)
    suspicious_level = IntegerField()
    has_dex = BooleanField(null=True)
    dexes = JSONField(null=True)

    class Meta:
        database = db

    def to_csv(self):
        """
        Export to CSV
        ["md5", "sha1", "sha256", "Package",
                        "App Name", "Cert Sha1", "Cert Subject", "Cert Issuer",
                        "Cert Serial", "Cert Not Before", "Cert Not After",
                        "Size", "VT Link", "VT Result", "Frosting", "Has Dex"
                        "Suspicious Level"]
        """
        res = [self.md5, self.sha1, self.sha256, self.package_name,
            self.app_name, self.certificate_sha1]
        res.append(self.certificate.get('subjectDN', ''))
        res.append(self.certificate.get('issuerDN', ''))
        res.append(self.certificate.get('serial', ''))
        res.append(self.certificate.get('not_before', ''))
        res.append(self.certificate.get('not_after', ''))
        res.append(self.size)
        if self.vt_link:
            res.append(self.vt_link)
        else:
            res.append('')
        if self.vt_positives is not None:
            res.append('{}/{}'.format(self.vt_positives, self.vt_total))
        else:
            res.append('')
        res.append("Yes" if self.frosting else "No")
        res.append("Yes" if self.has_dex else "No")
        res.append(["Low", "Medium", "High"][self.suspicious_level-1])
        return res

    def to_json(self):
        """
        Export Apk to json
        """
        return {
            "md5": self.md5,
            "sha1": self.sha1,
            "sha256": self.sha256,
            "package_name": self.package_name,
            "app_name": self.app_name,
            "certificate": self.certificate,
            "size": self.size,
            "koodous_link": self.koodous_link,
            "vt_link": self.vt_link,
            "vt_positives": self.vt_positives,
            "vt_total": self.vt_total,
            "frosting": self.frosting,
            "has_dex": self.has_dex,
            "dexes": self.dexes,
            "suspicious_level": self.suspicious_level
        }


db.connect()
db.create_tables([Phone, Apk])


#----------------------------------- Views ------------------------------------
@app.route('/')
def hello():
    phones = Phone.select()
    apks = {}
    for p in phones:
        apks[p.id] = len(Apk.select().join(Phone).where(Phone.id == p.id))
    return render_template('index.html', phones=phones, apks=apks)


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
