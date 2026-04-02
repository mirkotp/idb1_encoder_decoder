from hashlib import sha1, sha256, sha384, sha512
from ecdsa import SigningKey, VerifyingKey
from construct import *
from idb1.construct_helpers import *
from datetime import datetime

# Signing options
sk = None
vk = None
signing_algos = dict(ecdsa_sha256=sha256, ecdsa_sha384=sha384, ecdsa_sha512=sha512)
hashfunc = None

def make_idb1():
    msg_mrz_td1 =   FocusedSeq("f", Const(b"\x07"), Const(b"\x3c"), "f" / StripLT(C40(Bytes(60))))
    msg_mrz_td3 =   FocusedSeq("f", Const(b"\x08"), Const(b"\x3c"), "f" / StripLT(C40(Bytes(60))))
    msg_can =       FocusedSeq("f", Const(b"\x09"), Const(b"\x04"), "f" / C40(Bytes(4)))
    msg_photo =     FocusedSeq("f", Const(b"\xF0"), "f" / Prefixed(VarInt, GreedyBytes))
    msg_eu_visa =   FocusedSeq("f", Const(b"\xF1"), "f" / Prefixed(VarInt, Struct(
        "issuing_member_state"  / FocusedSeq("f", Const(b"\x00"), "f" / C40(Bytes(2))),
        "full_name"             / FocusedSeq("f", Const(b"\x01"), "f" / Prefixed(VarInt, C40(GreedyBytes))),
        "surname_at_birth"      / FocusedSeq("f", Const(b"\x02"), "f" / Prefixed(VarInt, C40(GreedyBytes))),
        "date_of_birth"         / FocusedSeq("f", Const(b"\x03"), "f" / Date(Bytes(3)))
    )))

    msg_signer_certificate = FocusedSeq("sc", Const(b"\x7e"), "sc" / Prefixed(VarInt, GreedyBytes))
    msg_signature_data =  FocusedSeq(
        "sig",
        Const(b"\x7f"),
        "sig" / Prefixed(VarInt, Signature(GreedyBytes, this._.signable.data, hashfunc=hashfunc, vk=vk, sk=sk))
    )

    idb1_message = Struct(
        "signable" / RawCopy(Struct(
            "header" / Struct (
                "country_identifier"      / C40(Bytes(2)),
                "signature_algorithm"     / If(this._._._.flags.signed, Enum(Byte, **dict((j,i) for (i,j) in enumerate(signing_algos.keys())))),
                "certificate_reference"   / If(this._._._.flags.signed, Bytes(5)),
                                            If(this._._._.flags.signed, Const(b"\x00")), # Date mask, no unknown fields
                "signature_creation_date" / If(this._._._.flags.signed, Date(Bytes(3)))
            ),
                
            Const(b"\x61"), # Message start
            "message" / Prefixed(VarInt, Struct (
                "mrz_td1"   / Optional(msg_mrz_td1),
                "mrz_td3"   / Optional(msg_mrz_td3),
                "can"       / Optional(msg_can),
                "photo"     / Optional(msg_photo),
                "eu_visa"   / Optional(msg_eu_visa)
            )),
        )),
        "signer_certificate"    / Optional(If(this._.flags.signed, msg_signer_certificate)),
        "signature_data"        / If(this._.flags.signed, msg_signature_data)
    )

    idb1 = Struct(
                        Const(b"NDB1"), # IDB Version 1 Signature
        "flags"     / FlagsEnum(
                            ExprAdapter(Byte, obj_ - 0x41, obj_ + 0x41),
                            signed = 1,
                            compressed = 2),
        "content"   / IfThenElse(
            this.flags.compressed, 
            Base32(Compressed(idb1_message, "zlib", level=9)), 
            Base32(idb1_message)
        )
    )

    return idb1

def parse(barcode, public=None):
    if public is not None:
        global vk
        vk = VerifyingKey.from_der(public)

    def clean_json(obj: dict):
        out = dict()
        for k, v in obj.items():
            if isinstance(v, dict):
                # if raw copy
                if "offset1" in v and "offset2" in v:
                    out[k] = clean_json(v["value"])
                else:
                    out[k] = clean_json(v)
            else:
                if v is not None and v is not False and not k.startswith("_"):
                    out[k] = v
        return out
    return clean_json(make_idb1().parse(barcode))

def build(obj, secret=None, public=None, includeCert=False):
    if obj["flags"]["signed"] is True:
        if secret is None:
            raise Exception("Unspecified signing key")
        if public is None:
            raise Exception("Unspecified public signer certificate")

        global sk
        sk = SigningKey.from_der(secret)
                
        global vk
        vk = VerifyingKey.from_der(public)
        
        if includeCert:
            obj["content"]["signer_certificate"] = public
        
        algo = obj["content"]["signable"]["value"]["header"]["signature_algorithm"]       
        if algo is None:
             raise Exception("Unspecified signing algorithm")

        if algo not in signing_algos.keys():
            raise Exception(f"Unknown signing algorithm: `{algo}`")

        global hashfunc
        hashfunc = signing_algos[algo]
        sk.default_hashfunc=signing_algos[algo]
        obj["content"]["signable"]["value"]["header"]["certificate_reference"] = sha1(public).digest()[-5:]
        date = int(datetime.now().strftime("%m%d%Y")).to_bytes(3)
        obj["content"]["signable"]["value"]["header"]["signature_creation_date"] = date

    return make_idb1().build(obj)
