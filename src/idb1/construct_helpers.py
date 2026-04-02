import base64
from construct import *

class Signature(Construct):
    def __init__(self, sigfield, bytesfunc, hashfunc=None, vk=None, sk=None):
        super().__init__()
        self.sigfield = sigfield
        self.bytesfunc = bytesfunc
        self.hashfunc = hashfunc
        self.vk = vk
        self.sk = sk

    def _parse(self, stream, context, path):
        sig = self.sigfield._parsereport(stream, context, path)
        if self.vk is None:
            raise Exception("Cannot check signature, you must specify a public signer certificate. Check the help for information.")
        else:
            try:
                self.vk.verify(sig, self.bytesfunc(context), hashfunc=self.hashfunc)
            except Exception as e:
                raise e
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
        string_date = str(int.from_bytes(obj, signed=False))
        if len(string_date) == 7:
            string_date = "0" + string_date
        
        return string_date[4:] + "-" + string_date[0:2] + "-" + string_date[2:4]

    def _encode(self, obj, context, path):
        # Not needed at the moment, expected input is 
        # int(THE_DATE.strftime("%m%d%Y")).to_bytes(3)
        return obj
