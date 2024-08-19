from .parser import idb1
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
        description='Reads or creates barcodes compliant with the ICAO Datastructure for Barcode')
       
    parser.add_argument('command', choices=["enc", "dec"], help="Subcommand: 'enc' for encoding a new barcode, 'dec' for decoding an existing one.")
    parser.add_argument('infile',  metavar="input_file", nargs='?', type=argparse.FileType('r'), default=sys.stdin, help="Specify a filename or provide through piping or redirect.")

    if len(sys.argv)==1:
        parser.print_help(sys.stderr)
        sys.exit(1)

    args = parser.parse_args()
    
    # Decoding
    if args.command == "dec":
        infile = args.infile.read().strip().encode()
        print(idb1.parse(infile))
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
                    "signer_certificate":   config.get("top", "signer_certificate", fallback=None),
                    "signature_data":       config.get("top", "signature_data", fallback=None)
                }
            }
        except configparser.NoOptionError as e:
            print(f"`{e.option}` option is required")
            quit()

        if obj["content"]["message"]["photo"] is not None:
            obj["content"]["message"]["photo"]= open(obj["content"]["message"]["photo"], "rb").read()

        print(idb1.build(obj).decode())
        quit()


if __name__ == "__main__":
    main()