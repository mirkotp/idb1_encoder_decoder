from .parser import parse, build
import argparse
import configparser
import sys


class MyParser(argparse.ArgumentParser):
    def error(self, message):
        sys.stderr.write('error: %s\n' % message)
        self.print_help()
        sys.exit(2)


def main():
    # Parsing args
    parser = MyParser(
        prog='idb1',
        description='Reads or creates barcodes compliant with the ICAO Datastructure for Barcode'
    )
       
    parser.add_argument('command', choices=["enc", "dec"], help="Subcommand: 'enc' for encoding a new barcode, 'dec' for decoding an existing one.")
    parser.add_argument('--secret', metavar="FILE", type=argparse.FileType('rb'), help="DER encoded file containing secret key.")
    parser.add_argument('--public', metavar="FILE", type=argparse.FileType('rb'), help="DER encoded file containing public signer certificate.")
    parser.add_argument("--include-cert", action=argparse.BooleanOptionalAction)
    parser.add_argument('infile',  metavar="input_file", nargs='?', type=argparse.FileType('r'), default=sys.stdin, help="Specify a filename or provide through piping or redirect.")

    if len(sys.argv)==1:
        parser.print_help(sys.stderr)
        sys.exit(1)

    args = parser.parse_intermixed_args()

    if args.command == "dec":
        decode(args)
    elif args.command == "enc":
        encode(args)


def decode(args):
    def pretty_print(obj: dict):
        for k, v in obj.items():
            if isinstance(v, dict):
                # if raw copy
                if "offset1" in v and "offset2" in v:
                    pretty_print(v["value"])
                else:
                    pretty_print(v)
            else:
                if v is not None and v is not False and not k.startswith("_"):
                    print(f"{k} = {v}")

    infile = args.infile.read().strip().encode()

    try:
        out = parse(
            infile, 
            public=args.public.read() if args.public else None
        )
        pretty_print(out)
    except Exception as e:
        print(e)


def encode(args):
    config = configparser.ConfigParser()
    config.read_string("[top]\n" + args.infile.read().strip())

    try:
        obj = {
            "flags": {
                "signed":       config.getboolean("top", "signed", fallback=False),
                "compressed":   config.getboolean("top", "compressed", fallback=False)
            },
            "content": {
                "signable": {
                    "value": {
                        "header": {
                            "country_identifier":       config.get("top", "country_identifier"),
                            "signature_algorithm":      config.get("top", "signature_algorithm", fallback=None),
                            "certificate_reference":    None,
                            "signature_creation_date":  None
                        },
                        "message": {
                            "vds": {
                                "vds_mrz":                  config.get("top", "vds_mrz", fallback=None),
                                "vds_number_of_entries":    config.getint("top", "vds_number_of_entries", fallback=None),
                                "vds_duration_of_stay": {
                                    "vds_duration_of_stay_days":     config.getint("top", "vds_duration_of_stay_days", fallback=None),
                                    "vds_duration_of_stay_months":   config.getint("top", "vds_duration_of_stay_months", fallback=None),
                                    "vds_duration_of_stay_years":    config.getint("top", "vds_duration_of_stay_years", fallback=None)
                                },
                                "vds_passport_number": config.get("top", "vds_passport_number", fallback=None),
                                "vds_visa_type": config.get("top", "vds_visa_type", fallback=None),
                            },
                            "mrz_td1":  config.get("top", "mrz_td1", fallback=None),
                            "mrz_td3":  config.get("top", "mrz_td3", fallback=None),
                            "can":      config.get("top", "can", fallback=None),
                            "photo":    config.get("top", "photo", fallback=None)
                        },
                    },
                },
                "signer_certificate":   None,
                "signature_data":       None
            }
        }
    except configparser.NoOptionError as e:
        print(f"`{e.option}` option is required")
        quit()

    if obj["content"]["signable"]["value"]["message"]["photo"] is not None:
        obj["content"]["signable"]["value"]["message"]["photo"] = open(obj["content"]["signable"]["value"]["message"]["photo"], "rb").read()
   
    out = build(
        obj, 
        secret=args.secret.read() if args.secret else None,
        public=args.public.read() if args.public else None,
        includeCert=args.include_cert
    ).decode()

    print(out)
        

if __name__ == "__main__":
    main()   