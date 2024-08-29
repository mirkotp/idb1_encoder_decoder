from .parser import idb1, loadVerifyingKey, loadSigningKey
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
    parser.add_argument('-c', '--cert', type=argparse.FileType('rb'), help="DER file containing secret keys for signing a barcode.")
    parser.add_argument('infile',  metavar="input_file", nargs='?', type=argparse.FileType('r'), default=sys.stdin, help="Specify a filename or provide through piping or redirect.")

    if len(sys.argv)==1:
        parser.print_help(sys.stderr)
        sys.exit(1)

    args = parser.parse_args()

    # Decoding
    if args.command == "dec":
        infile = args.infile.read().strip().encode()

        if args.cert is not None:
            loadVerifyingKey(args.cert.read())

        try:
            out = idb1.parse(infile)
        except Exception as e:
            print(e)
            quit()

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
        
        pretty_print(out)
        quit()
    
    # Encoding
    if args.command == "enc":
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
                                "certificate_reference":    config.get("top", "certificate_reference", fallback=None),
                                "signature_creation_date":  config.get("top", "signature_creation_date", fallback=None)
                            },
                            "message": {
                                "mrz_td1":  config.get("top", "mrz_td1", fallback=None),
                                "mrz_td3":  config.get("top", "mrz_td3", fallback=None),
                                "can":      config.get("top", "can", fallback=None),
                                "photo":    config.get("top", "photo", fallback=None)
                            },
                        },
                    },
                    "signer_certificate":   config.get("top", "signer_certificate", fallback=None),
                    "signature_data":       config.get("top", "signature_data", fallback=None)
                }
            }
        except configparser.NoOptionError as e:
            print(f"`{e.option}` option is required")
            quit()

        if obj["content"]["signable"]["value"]["message"]["photo"] is not None:
            obj["content"]["signable"]["value"]["message"]["photo"] = open(obj["content"]["signable"]["value"]["message"]["photo"], "rb").read()

        if args.cert is not None:
            loadSigningKey(args.cert.read())
       
        print(idb1.build(obj).decode())
        quit()


if __name__ == "__main__":
    main()