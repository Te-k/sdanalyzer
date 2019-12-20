import os
import sys
import argparse
import threading
import webbrowser
from androguard.core import androconf
from androguard.core.bytecodes.axml import ResParserError
from .app import app, Phone, Apk
from .utils import get_db_path, extract_apk_infos, get_sha256, check_vt, get_koodous_report, get_suspicious_level


def add_apk(apkpath, phone):
    res = extract_apk_infos(apkpath)
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
    apk.suspicious = None
    vt = check_vt(res['sha256'])
    if vt['found']:
        apk.vt_link = vt['permalink']
        apk.vt_positives = vt['positives']
        apk.vt_total = vt['total']
    else:
        apk.vt_link = None
    k = get_koodous_report(res['sha256'])
    if k:
        apk.koodous_link = "https://koodous.com/apks/{}".format(res['sha256'])
    apk.suspicious_level = get_suspicious_level(apk)
    apk.save()


def main():
    parser = argparse.ArgumentParser(description='Launches sdanalyzer')
    subparsers = parser.add_subparsers(help='Subcommand')
    parser_a = subparsers.add_parser('serve', help='Launch the web app')
    parser_a.add_argument('--debug', '-D', action='store_true', help='debug mode')
    parser_a.add_argument('--port', '-p', type=int, default=5000,
            help='Port used by the web server')
    parser_a.set_defaults(subcommand='serve')
    parser_b = subparsers.add_parser('flush', help='Flush the database')
    parser_b.set_defaults(subcommand='flush')
    parser_c = subparsers.add_parser('phones', help='List phones')
    parser_c.add_argument('--create', '-c', help='Create a new phone')
    parser_c.set_defaults(subcommand='phones')
    parser_d = subparsers.add_parser('import', help='Import apks')
    parser_d.add_argument('--phone', '-p', help="Phone id", type=int)
    parser_d.add_argument("APK", help="APK or folder path")
    parser_d.set_defaults(subcommand='import')
    args = parser.parse_args()


    if 'subcommand' in args:
        if args.subcommand == 'serve':
            if not args.debug:
                # We launch a browser with some delay.
                url = 'http://127.0.0.1:{}'.format(args.port)
                threading.Timer(1.25, lambda: webbrowser.open(url) ).start()

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
            else:
                phones = Phone.select()
                for p in phones:
                    # TODO : add number of APKs
                    print("{}\t{}\t{}".format(p.id, p.name, p.model))
        elif args.subcommand == 'import':
            if not args.phone:
                print("Please provide the phone id")
                sys.exit(0)
            phone = Phone.get(Phone.id == args.phone)
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
                add_apk(args.APK, phone)
                print("APK {} added to the phone".format(args.APK))
            elif os.path.isdir(args.APK):
                failed = []
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
                            add_apk(pp, phone)
                            print("APK {} added to the phone".format(pp))
                            imported += 1
                        else:
                            print("{} is not a file".format(pp))
                    except ResParserError:
                        failed.append(pp)
                        print("Parsing Error from androguard, this app will be ignored")
                print("")
                print("{} applications imported".format(imported))
                if len(failed) > 0:
                    print("{} applications could not be imported:".format(len(failed)))
                    for f in failed:
                        print("-{}".format(f))
            else:
                print("Invalid path")
        else:
            parser.print_help()
    else:
        parser.print_help()
