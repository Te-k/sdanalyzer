import os
import re
import hashlib
import requests
from androguard.misc import AnalyzeAPK
from androguard.core import androconf


SUSPICIOUS_PERMISSIONS  = [
    'android.permission.INTERNET',
    'android.permission.ACCESS_FINE_LOCATION',
    'android.permission.READ_CONTACTS',
    'android.permission.READ_SMS',
    'android.permission.RECORD_AUDIO',
    'android.permission.CAMERA',
    'android.permission.READ_CALL_LOG',
    'android.permission.READ_CONTACTS',
    'android.permission.READ_EXTERNAL_STORAGE'
]


def count_suspicious_permissions(permissions):
    return len([p for p in permissions if p in SUSPICIOUS_PERMISSIONS])


def get_db_path():
    config_dir = os.path.expanduser('~/.config/sdanalyzer')
    if not os.path.isdir(config_dir):
        os.mkdir(config_dir)
    db_path = os.path.join(config_dir, 'db.db')
    return db_path


def get_sha256(path):
    """
    returns sha256 of a file
    """
    sha256 = hashlib.sha256()
    with open(path, 'rb') as f:
        data = f.read()
    sha256.update(data)
    return sha256.hexdigest()


def check_vt(sha256):
    """
    Check if a hash is on VT
    """
    apikey = "233f22e200ca5822bd91103043ccac138b910db79f29af5616a9afe8b6f215ad"
    url = "https://www.virustotal.com/partners/sysinternals/file-reports?apikey={}".format(apikey)
    items = []
    items.append({
        "hash": sha256,
        "image_path": "unknown",
        "creation_datetime": "unknown",
    })
    headers = {"User-Agent": "VirusTotal", "Content-Type": "application/json"}
    res = requests.post(url, headers=headers, json=items)
    if res.status_code == 200:
        report = res.json()
        return report["data"][0]
    return None


def get_koodous_report(sha256):
    url = "https://api.koodous.com/apks/{}".format(sha256)
    res = requests.get(url)
    if res.status_code == 404 :
        return None
    return res.json()


def convert_x509_name(name):
    """
    Convert x509 name to a string
    """
    types = {
        'country_name': 'C',
        'state_or_province_name': 'ST',
        'locality_name': 'L',
        'organization_name': 'O',
        'organizational_unit_name': 'OU',
        'common_name': 'CN',
        'email_address': 'emailAddress'
    }

    return '/'.join(['{}={}'.format(types[attr], name.native[attr]) for attr in name.native])


def get_urls(apk):
    """
    Extract urls from data
    """
    res = []
    for dex in apk.get_all_dex():
        res += re.findall(b'http[s]?://(?:[a-zA-Z]|[0-9]|[$-_@.&+]|[!*\(\),]|(?:%[0-9a-fA-F][0-9a-fA-F]))+', dex)
    return [s.decode('utf-8') for s in res]


def get_strings(apk):
    """
    Extract all strings
    """
    res = []
    for dex in apk.get_all_dex():
        res += re.findall(b"[\x1f-\x7e]{6,}", dex)
        res += re.findall(b"(?:[\x1f-\x7e][\x00]){6,}", dex)
    return [s.decode('utf-8') for s in res]


def get_suspicious_level(apk):
    """
    Compute suspicious level
    1 : Low
    2 : Medium
    3 : High
    """
    level = 1
    if apk.vt_link:
        if apk.vt_positives > 5:
            level = 3
        elif apk.vt_positives > 0:
            level = 2
    else:
        level = 2
    if apk.permissions_suspicious > 5:
        level = max(level, 2)
    # TODO : ass list o known good certificates
    return level


def extract_apk_infos(apk_path):
    """
    Extract informations from an APK
    """
    sha256 = hashlib.sha256()
    sha1 = hashlib.sha1()
    md5 = hashlib.md5()
    with open(apk_path, 'rb') as f:
        data = f.read()
    sha256.update(data)
    sha1.update(data)
    md5.update(data)

    apk, dex, dexes = AnalyzeAPK(apk_path)
    res = {
        'sha256': sha256.hexdigest(),
        'sha1': sha1.hexdigest(),
        'md5': md5.hexdigest(),
        'manifest': apk.get_android_manifest_axml().get_xml(),
        'app_name': apk.get_app_name(),
        'package_name': apk.get_package(),
        'certificate': {},
        'signature_name': apk.get_signature_name(),
        'permissions': apk.get_permissions(),
        'suspicious_permissions': count_suspicious_permissions(apk.get_permissions()),
        'urls': get_urls(apk),
        'strings': get_strings(apk),
        'size': len(data)
    }
    if len(apk.get_certificates()) > 0:
        cert = apk.get_certificates()[0]
        res['certificate']['sha1'] = cert.sha1_fingerprint.replace(' ', '')
        res['certificate']['serial'] = '{:X}'.format(cert.serial_number)
        res['certificate']['issuerDN'] = convert_x509_name(cert.issuer)
        res['certificate']['subjectDN'] = convert_x509_name(cert.subject)
        res['certificate']['not_before'] = cert['tbs_certificate']['validity']['not_before'].native.strftime('%b %-d %X %Y %Z')
        res['certificate']['not_after'] = cert['tbs_certificate']['validity']['not_after'].native.strftime('%b %-d %X %Y %Z')

    return res

