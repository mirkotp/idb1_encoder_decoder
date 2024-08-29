import base64
import hashlib
from ecdsa import SigningKey, VerifyingKey, curves
from construct import *

def loadSigningKey(der):
    global sk
    sk = SigningKey.from_der(der)

def loadVerifyingKey(der):
    global vk
    vk = VerifyingKey.from_der(der)


sk = SigningKey.generate(curve=curves.SECP256k1, hashfunc=hashlib.sha256)
vk: VerifyingKey = sk.verifying_key

class Signature(Construct):
    def __init__(self, sigfield, bytesfunc):
        super().__init__()
        self.sigfield = sigfield
        self.bytesfunc = bytesfunc

    def _parse(self, stream, context, path):
        sig = self.sigfield._parsereport(stream, context, path)
        if vk.verify(sig, self.bytesfunc(context)) is not True:
            raise Exception("invalid signature")
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
    
msg_mrz_td1 = FocusedSeq("mrz", Const(b"\x07"), Const(b"\x3c"), "mrz" / StripLT(C40(Bytes(60))))
msg_mrz_td3 = FocusedSeq("mrz", Const(b"\x08"), Const(b"\x3c"), "mrz" / StripLT(C40(Bytes(60))))
msg_can = FocusedSeq("code", Const(b"\x09"), Const(b"\x04"), "code" / C40(Bytes(4)))
msg_photo = FocusedSeq("p", Const(b"\xF0"), "p" / Prefixed(VarInt, GreedyBytes))

msg_signer_certificate = Optional(FocusedSeq("sc", Const(b"\x7e"), "sc" / Prefixed(VarInt, GreedyBytes)))
msg_signature_data =  FocusedSeq(
    "sig",
    Const(b"\x7f"),
    "sig" / Prefixed(VarInt, Signature(GreedyBytes, this._.signable.data))
)

idb1_message = Struct(
    "signable" / RawCopy(Struct(
        "header" / Struct (
            "country_identifier"      / C40(Bytes(2)),
            # "signature_algorithm"     / If(this._._._.flags.signed, Bytes(1)), # Check if Optional is really needed
            # "certificate_reference"   / If(this._._._.flags.signed, Bytes(5)),
            # "signature_creation_date" / If(this._._._.flags.signed, Bytes(4))
        ),
            
        Const(b"\x61"), # Message start
        "message" / Prefixed(VarInt, Struct (
            "mrz_td1"   / Optional(msg_mrz_td1),
            "mrz_td3"   / Optional(msg_mrz_td3),
            "can"       / Optional(msg_can),
            "photo"     / Optional(msg_photo)
        )),
    )),
    "signer_certificate"    / If(this._.flags.signed, msg_signer_certificate),
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

