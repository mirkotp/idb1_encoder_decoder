import base64
from construct import *

setGlobalPrintFullStrings(True)
setGlobalPrintFalseFlags(True)

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
                output += b"\xfe" + (u1 + 1).to_bytes()
                break
            u1 = chset.index(chr(u1))
            u2 = chset.index(chr(u2))
            u3 = 0 if u3 == 0 else chset.index(chr(u3))
            u = 1600*u1 + 40*u2 + u3 + 1
            output += int(u / 256).to_bytes() + int(u % 256).to_bytes()
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
msg_signer_certificate = FocusedSeq("sc", Const(b"\x7f"), "sc" / Prefixed(VarInt, GreedyBytes))
msg_signature_data = FocusedSeq("sd", Const(b"\x7f"), "sd" / Prefixed(VarInt, GreedyBytes))

idb1_message = Struct(
    "header" / Struct (
        "country_identifier"      / C40(Bytes(2)),
        "signature_algorithm"     / Optional(If(this._._.flags.signed, Bytes(1))), # Check if Optional is really needed
        "certificate_reference"   / Optional(If(this._._.flags.signed, Bytes(5))),
        "signature_creation_date" / Optional(If(this._._.flags.signed, Bytes(4)))
    ),
        
    Const(b"\x61"), # Message start
    "message" / Prefixed(VarInt, Struct (
        "mrz_td1" / Optional(msg_mrz_td1),
        "mrz_td3" / Optional(msg_mrz_td3),
        "can" / Optional(msg_can),
        "photo" / Optional(msg_photo)
    )),

    "signer_certificate" / Optional(msg_signer_certificate),
    "signature_data" / Optional(msg_signature_data)
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

