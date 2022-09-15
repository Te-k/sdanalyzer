import os
import sys
import csv
import json
import argparse
import threading
import webbrowser
import logging
import time
import yara
from peewee import DoesNotExist
from androguard.core import androconf
from androguard.core.bytecodes.axml import ResParserError
from .app import app, Phone, Apk
from .utils import get_db_path, extract_apk_infos, get_sha256, check_vt, get_suspicious_level


def add_apk(apkpath, phone, rules):
    res = extract_apk_infos(apkpath, rules)
    apk = Apk()
    apk.owner = phone
    apk.path = os.path.abspath(apkpath)
    apk.md5 = res['md5']
    apk.sha1 = res['sha1']
    apk.sha256 = res['sha256']
    apk.package_name = res['package_name']
    apk.app_name = res['app_name']
    apk.manifest = res['manifest']
    if len(res['certificate']) > 0:
        apk.certificate_sha1 = res['certificate']['sha1']
        apk.certificate = res['certificate']
    apk.certificate_trusted = res['trusted_cert']
    apk.certificate_trusted_name = res['trusted_cert_name']
    apk.permissions = res['permissions']
    apk.permissions_suspicious = res['suspicious_permissions']
    apk.urls = res['urls']
    apk.strings = res['strings']
    apk.size = res['size']
    apk.frosting = res['frosting']
    apk.split = res['split']
    apk.suspicious = None
    apk.vt_check = False
    apk.has_dex = (len(res['dexes'].keys()) > 0)
    apk.dexes = res['dexes']
    apk.yara = res['yara']
    apk.suspicious_level = get_suspicious_level(apk)
    apk.save()
    return apk


def chunks(lst, n):
    """Yield successive n-sized chunks from lst."""
    for i in range(0, len(lst), n):
        yield lst[i:i + n]


def check_hashes_vt(hashes, phone):
    for chunk in chunks(hashes, 25):
        res = check_vt(chunk)
        for h in res:
            apk = list(Apk.select().join(Phone).where(Phone.id == phone.id, Apk.sha256 == h['hash']))
            if len(apk) != 1:
                continue
            else:
                apk = apk[0]
            if h['found']:
                apk.vt_link = h['permalink']
                apk.vt_positives = h['positives']
                apk.vt_total = h['total']
                apk.vt_check = True
                apk.save()
            else:
                apk.vt_check = True
                apk.save()
        time.sleep(0.25)


def main():
    parser = argparse.ArgumentParser(description='Launches sdanalyzer')
    subparsers = parser.add_subparsers(help='Subcommand')
    parser_a = subparsers.add_parser('serve', help='Launch the web app')
    parser_a.add_argument('--debug', '-D', action='store_true', help='debug mode')
    parser_a.add_argument(
        '--port', '-p', type=int, default=5000,
        help='Port used by the web server')
    parser_a.set_defaults(subcommand='serve')
    parser_b = subparsers.add_parser('flush', help='Flush the database')
    parser_b.set_defaults(subcommand='flush')
    parser_c = subparsers.add_parser('phones', help='List phones')
    parser_c.add_argument('--create', '-c', help='Create a new phone')
    parser_c.add_argument('--phone', '-p', help='Give information on a phone')
    parser_c.set_defaults(subcommand='phones')
    parser_d = subparsers.add_parser('import', help='Import apks')
    parser_d.add_argument('--phone', '-p', help="Phone id")
    parser_d.add_argument('--yara', '-y', help="Additional YARA rules")
    parser_d.add_argument("APK", help="APK or folder path")
    parser_d.set_defaults(subcommand='import')
    parser_e = subparsers.add_parser('delete', help='Delete a phone and related data')
    parser_e.add_argument('PHONE',  help="Phone id or name")
    parser_e.set_defaults(subcommand='delete')
    parser_f = subparsers.add_parser('export', help='Export information on all apks of a phone')
    parser_f.add_argument('PHONE',  help="Phone id or name")
    parser_f.add_argument('--format', '-f', default="csv", choices=["csv", "json"], help="Export format")
    parser_f.add_argument('--output', '-o', help="Output filename")
    parser_f.set_defaults(subcommand='export')
    args = parser.parse_args()

    logging.getLogger("androguard.apk").setLevel(logging.CRITICAL)
    logging.getLogger("dad").setLevel(logging.CRITICAL)
    logging.getLogger("androguard").setLevel(logging.CRITICAL)

    if 'subcommand' in args:
        if args.subcommand == 'serve':
            if not args.debug:
                # We launch a browser with some delay.
                url = 'http://127.0.0.1:{}'.format(args.port)
                threading.Timer(1.25, lambda: webbrowser.open(url)).start()

            # launch the flask app
            app.run(port=args.port, debug=args.debug)
        elif args.subcommand == 'flush':
            db = get_db_path()
            if os.path.isfile(db):
                os.remove(get_db_path())
            print("Database deleted")
        elif args.subcommand == 'phones':
            if args.create:
                p = Phone(name=args.create)
                p.save()
                print("{}\t{}\t{}".format(p.id, p.name, p.model))
            elif args.phone:
                try:
                    phone = Phone.find_id_or_name(args.phone)
                    print("Id: {}".format(phone.id))
                    print("Name: {}".format(phone.name))
                    print("Model: {}".format(phone.model))
                    apkn = Apk.select().where(Apk.owner == phone).count()
                    print("#Apks: {}".format(apkn))
                except DoesNotExist:
                    print("Phone not found")
            else:
                phones = Phone.select()
                if len(phones) == 0:
                    print("No phones in the database")
                for p in phones:
                    apkn = Apk.select().where(Apk.owner == p).count()
                    print("{}\t{}\t{}\t{} apks".format(p.id, p.name, p.model, apkn))
        elif args.subcommand == 'import':
            if not args.phone:
                print("Please provide the phone id")
                sys.exit(0)
            try:
                phone = Phone.find_id_or_name(args.phone)
            except DoesNotExist:
                print("Phone not found")
                sys.exit(0)
            # Get Yara rules
            path = os.path.join(os.path.realpath(__file__)[:-8], 'data/rules.yar')
            rules = [yara.compile(filepath=path)]
            if args.yara:
                if not os.path.isfile(args.yara):
                    print("The yara file does not exist, skipping")
                else:
                    rules.append(yara.compile(filepath=args.yara))
            if os.path.isfile(args.APK):
                ret_type = androconf.is_android(args.APK)
                if ret_type != "APK":
                    print("Not an APK file")
                    sys.exit(1)
                h = get_sha256(args.APK)
                a = len(Apk.select().join(Phone).where(Phone.id == phone.id, Apk.sha256 == h))
                if a > 0:
                    print("This APK is already in the database")
                    sys.exit(0)
                add_apk(args.APK, phone, rules)
                check_hashes_vt([h], phone)
                print("APK {} added to the phone".format(args.APK))
            elif os.path.isdir(args.APK):
                failed = []
                hashes = []
                risks = []
                imported = 0
                for f in os.listdir(args.APK):
                    try:
                        pp = os.path.join(args.APK, f)
                        if os.path.isfile(pp):
                            print("Importing {}".format(pp))
                            ret_type = androconf.is_android(pp)
                            if ret_type != "APK":
                                print("{} is not an APK file".format(pp))
                                continue
                            h = get_sha256(pp)
                            a = len(Apk.select().join(Phone).where(Phone.id == phone.id, Apk.sha256 == h))
                            if a > 0:
                                print("This APK {} is already in the database".format(pp))
                                continue
                            apk = add_apk(pp, phone, rules)
                            hashes.append(h)
                            print("APK {} added to the phone".format(pp))
                            imported += 1
                        else:
                            print("{} is not a file".format(pp))
                    except (ResParserError, ValueError) as e:
                        failed.append(pp)
                        print("Parsing Error from androguard, this app will be ignored")
                        print(e)
                print("Checking VirusTotal")
                check_hashes_vt(hashes, phone)
                # Compute risk levels
                for apk in Apk.select().join(Phone).where(Phone.id == phone.id):
                    apk.suspicious_level = get_suspicious_level(apk)
                    risks.append(apk.suspicious_level)
                    apk.save()
                print("")
                print("{} applications imported".format(imported))
                print("Risk levels: Low {} - Medium {} - High {}".format(
                    risks.count(1), risks.count(2), risks.count(3)))
                if len(failed) > 0:
                    print("{} applications could not be imported:".format(len(failed)))
                    for f in failed:
                        print("-{}".format(f))
            else:
                print("Invalid path")
        elif args.subcommand == 'delete':
            # Delete the phone
            try:
                phone = Phone.find_id_or_name(args.PHONE)
            except DoesNotExist:
                print("Phone not found")
                sys.exit(0)
            else:
                if input("are you sure you want to delete this phone? (y/n)") != "y":
                    print("Cancelled")
                    sys.exit(0)
                query = Apk.delete().where(Apk.owner == phone)
                apknb = query.execute()
                print("{} apks deleted".format(apknb))
                phone.delete_instance()
                print("Phone {} deleted".format(args.PHONE))
        elif args.subcommand == 'export':
            try:
                phone = Phone.find_id_or_name(args.PHONE)
            except DoesNotExist:
                print("Phone not found")
                sys.exit(0)
            if args.format == "csv":
                if args.output:
                    output = args.output
                else:
                    output = "{}.csv".format(phone.name.replace(' ', ''))
                with open(output, 'w') as csvfile:
                    csvwriter = csv.writer(csvfile, delimiter=',', quotechar='"')
                    csvwriter.writerow([
                        "md5", "sha1", "sha256", "Package",
                        "App Name", "Cert Sha1", "Cert Subject", "Cert Issuer",
                        "Cert Serial", "Cert Not Before", "Cert Not After",
                        "Size", "VT Link", "VT Result", "Frosting", "Has Dex",
                        "Suspicious Level"])
                    for apk in Apk.select().where(Apk.owner == phone):
                        csvwriter.writerow(apk.to_csv())
            else:
                if args.output:
                    output = args.output
                else:
                    output = "{}.json".format(phone.name.replace(' ', ''))
                data = {}
                for apk in Apk.select().where(Apk.owner == phone):
                    data[apk.sha256] = apk.to_json()
                with open(output, "w+") as f:
                    f.write(json.dumps(data))
            print("Data dumped in {}".format(output))
        else:
            parser.print_help()
    else:
        print("No command given, assuming you wanted to launch the web server")
        # We launch a browser with some delay.
        url = 'http://127.0.0.1:{}'.format(5000)
        threading.Timer(1.25, lambda: webbrowser.open(url)).start()
        # launch the flask app
        app.run(port=5000, debug=False)

        parser.print_help()
