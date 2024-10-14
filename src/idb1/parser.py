import base64
import sys
from hashlib import sha256, sha384, sha512
from ecdsa import SigningKey, VerifyingKey
from construct import *
from datetime import datetime

# Signing options
sk = None
vk = None
signing_algos = dict(ecdsa_sha256=sha256, ecdsa_sha384=sha384, ecdsa_sha512=sha512)

class Signature(Construct):
    def __init__(self, sigfield, bytesfunc):
        super().__init__()
        self.sigfield = sigfield
        self.bytesfunc = bytesfunc

    def _parse(self, stream, context, path):
        sig = self.sigfield._parsereport(stream, context, path)
        if vk is None:
            print(">>>>>>>>> SIGNATURE: cannot check signature, you must specify a public signer certificate. Check the help for information.", file=sys.stderr)
        else:
            try:
                vk.verify(sig, self.bytesfunc(context), hashfunc=sha512)
                print(">>>>>>>>> SIGNATURE: valid")
            except:
                print(">>>>>>>>> SIGNATURE: invalid signature or wrong certificate.", file=sys.stderr)
        return sig

    def _build(self, obj, stream, context, path):
        sig = sk.sign(self.bytesfunc(context))
        self.sigfield._build(sig, stream, context, path)
        return sig

    def _sizeof(self, context, path):
        return self.sigfield._sizeof(context, path)

class Base32(Tunnel):
    def _decode(self, obj, context, path):
        obj = obj + b"=" * ((8 - len(obj) % 8) % 8)
        return base64.b32decode(obj)

    def _encode(self, obj, context, path):
        return base64.b32encode(obj).strip(b"=")

class C40(Adapter):
    def _decode(self, obj, context, path):
        chset = "*** 0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ"
        output = ''
        for b1, b2  in [(obj[i:] + b"\x00")[0:2] for i in range(0, len(obj), 2)]:
            if b1 == 254:
                output += chr(b2 - 1)
                break
            u = (b1 * 256) + b2
            u1 = int((u - 1) / 1600)
            u2 = int((u - (u1 * 1600) - 1) / 40)
            u3 = int(u - (u1 * 1600) - (u2 * 40) - 1)
            output += chset[u1] + chset[u2] + chset[u3]
        return output

    def _encode(self, obj, context, path):
        obj = obj.encode()
        chset = "*** 0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ"
        output = b''
        for u1, u2, u3 in [(obj[i:] + b"\x00\x00")[0:3] for i in range(0, len(obj), 3)]:
            if u2 == 0:
                output += b"\xfe" + (u1 + 1).to_bytes(1, "big")
                break
            u1 = chset.index(chr(u1))
            u2 = chset.index(chr(u2))
            u3 = 0 if u3 == 0 else chset.index(chr(u3))
            u = 1600*u1 + 40*u2 + u3 + 1
            output += int(u / 256).to_bytes(1, "big") + int(u % 256).to_bytes(1, "big")
        return output

class StripLT(Adapter):
    def _decode(self, obj, context, path):
        return obj.replace(" ", "<")

    def _encode(self, obj, context, path):
        return obj.replace("<", " ")
    
class Date(Adapter):
    def _decode(self, obj, context, path):
        string_date = str(int.from_bytes(obj, signed=False))
        if len(string_date) == 7:
            string_date = "0" + string_date
        
        return string_date[4:] + "-" + string_date[0:2] + "-" + string_date[2:4]

    def _encode(self, obj, context, path):
        # Not needed at the moment
        return obj

msg_mrz_td1 = FocusedSeq("mrz", Const(b"\x07"), Const(b"\x3c"), "mrz" / StripLT(C40(Bytes(60))))
msg_mrz_td3 = FocusedSeq("mrz", Const(b"\x08"), Const(b"\x3c"), "mrz" / StripLT(C40(Bytes(60))))
msg_can = FocusedSeq("code", Const(b"\x09"), Const(b"\x04"), "code" / C40(Bytes(4)))
msg_photo = FocusedSeq("p", Const(b"\xF0"), "p" / Prefixed(VarInt, GreedyBytes))

msg_signer_certificate = FocusedSeq("sc", Const(b"\x7e"), "sc" / Prefixed(VarInt, GreedyBytes))
msg_signature_data =  FocusedSeq(
    "sig",
    Const(b"\x7f"),
    "sig" / Prefixed(VarInt, Signature(GreedyBytes, this._.signable.data))
)

idb1_message = Struct(
    "signable" / RawCopy(Struct(
        "header" / Struct (
            "country_identifier"      / C40(Bytes(2)),
            "signature_algorithm"     / If(this._._._.flags.signed, Enum(Byte, **dict((j,i) for (i,j) in enumerate(signing_algos.keys())))),
            "certificate_reference"   / If(this._._._.flags.signed, Bytes(5)),
                                        If(this._._._.flags.signed, Const(b"0x00")), # Date mask, no unknown fields
            "signature_creation_date" / If(this._._._.flags.signed, Date(Bytes(3)))
        ),
            
        Const(b"\x61"), # Message start
        "message" / Prefixed(VarInt, Struct (
            "mrz_td1"   / Optional(msg_mrz_td1),
            "mrz_td3"   / Optional(msg_mrz_td3),
            "can"       / Optional(msg_can),
            "photo"     / Optional(msg_photo)
        )),
    )),
    "signer_certificate"    / Optional(If(this._.flags.signed, msg_signer_certificate)),
    "signature_data"        / If(this._.flags.signed, msg_signature_data)
)

idb1 = Struct(
                    Const(b"NDB1"), # IDB Version 1 Signature
    "flags"       / FlagsEnum(
                        ExprAdapter(Byte, obj_ - 0x41, obj_ + 0x41),
                        signed = 1,
                        compressed = 2),
    "content" / IfThenElse(
        this.flags.compressed, 
        Base32(Compressed(idb1_message, "zlib", level=9)), 
        Base32(idb1_message)
    )
)

def parse(barcode, public=None):
    if public is not None:
        global vk
        vk = VerifyingKey.from_der(public)
    return idb1.parse(barcode)

def build(obj, secret=None, public=None, includeCert=False):
    if obj["flags"]["signed"] is True:
        if secret is None:
            print("When `signed = True`, you must specify you secret key. Check help for more information.")
            quit()

        global sk
        sk = SigningKey.from_der(secret)
                
        if public is None:
            print("When `signed = True`, you must specify your public signer ceritifcate. Check help for more information.")
            quit()

        global vk
        vk = VerifyingKey.from_der(public)
        
        if includeCert:
            obj["content"]["signer_certificate"] = public
        
        algo = obj["content"]["signable"]["value"]["header"]["signature_algorithm"]       
        if algo is None:
            print("`signature_algorithm` is required when `signed = True`, check the docs for possible values.")
            quit()

        if algo not in signing_algos.keys():
            print(f"`{algo}` is not a supported signing algorithm, check the docs for possible values.")
            quit()

        sk.default_hashfunc=signing_algos[algo]
        obj["content"]["signable"]["value"]["header"]["certificate_reference"] = public[-5:]

        date = int(datetime.now().strftime("%m%d%Y")).to_bytes(3)
        obj["content"]["signable"]["value"]["header"]["signature_creation_date"] = date

    return idb1.build(obj)
