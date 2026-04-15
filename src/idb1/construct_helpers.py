import base64
from hashlib import sha256, sha384, sha512
from construct import *

SIGNING_ALGOS = dict(ecdsa_sha256=sha256, ecdsa_sha384=sha384, ecdsa_sha512=sha512)

def as_instance(arg): 
    x = arg()
    return x

@as_instance
class DerLengthInt(Construct):
    def _parse(self, stream, context, path):
        b = stream_read(stream, 1, path)
        if b[0] >= 0b10000000:
            num_bytes = b[0] & 0b01111111
            b = stream_read(stream, num_bytes, path)
        return int.from_bytes(b, 'big')

    def _build(self, obj, stream, context, path):
        if not isinstance(obj, int):
            raise IntegerError(f"value {obj} is not an integer", path=path)
        if obj < 0:
            raise IntegerError(f"DerLengthInt cannot build from negative number {obj}", path=path)
        x = obj
        B = bytearray()
        bytes_needed = (x.bit_length() + 7) // 8
        if x >= 0b10000000:
            B.append(0b10000000 | (bytes_needed & 0b01111111))
        ba = bytearray(x.to_bytes(max(bytes_needed, 1), 'big'))
        B += ba
        stream_write(stream, bytes(B), len(B), path)
        return obj

class Signature(Construct):
    def __init__(self, sigfield, bytesfunc, vk=None, sk=None):
        super().__init__()
        self.sigfield = sigfield
        self.bytesfunc = bytesfunc
        self.vk = vk
        self.sk = sk

    def _parse(self, stream, context, path):
        sig = self.sigfield._parsereport(stream, context, path)
        if self.vk is None:
            raise Exception("Cannot check signature, you must specify a public signer certificate. Check the help for information.")
        else:
            self.vk.verify(sig, self.bytesfunc(context), hashfunc=SIGNING_ALGOS[context._.signable.value.header.signature_algorithm])
        return sig

    def _build(self, obj, stream, context, path):
        sig = self.sk.sign(self.bytesfunc(context))
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
            output += chset[u1] + chset[u2] + (chset[u3] if u3 != 0 else "")
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
        mask = obj[0]
        string_date = str(int.from_bytes(obj[1:], signed=False))
        if len(string_date) == 7:
            string_date = "0" + string_date

        for i in range(8):
            if (mask >> i) & 1:
                string_date = string_date[:i] + "X" + string_date[i+1:]
        return string_date[4:] + "-" + string_date[0:2] + "-" + string_date[2:4]

    def _encode(self, obj, context, path):

        # Not needed at the moment, expected input is 
        # int(THE_DATE.strftime("%m%d%Y")).to_bytes(3)
        return obj
