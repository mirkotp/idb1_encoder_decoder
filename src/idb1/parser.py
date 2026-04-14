from hashlib import sha1
from ecdsa import SigningKey, VerifyingKey
from construct import *
from idb1.construct_helpers import *
from datetime import datetime

def make_idb1(sk=None, vk=None):
    # IDB Messages
    msg_mrz_td1 =   FocusedSeq("f", Const(b"\x07"), Const(b"\x3c"), "f" / StripLT(C40(Bytes(60))))
    msg_mrz_td3 =   FocusedSeq("f", Const(b"\x08"), Const(b"\x3c"), "f" / StripLT(C40(Bytes(60))))
    msg_can =       FocusedSeq("f", Const(b"\x09"), Const(b"\x04"), "f" / C40(Bytes(4)))
    msg_photo =     FocusedSeq("f", Const(b"\x1B"), "f" / Prefixed(DerLengthInt, GreedyBytes))
    msg_eu_visa =   FocusedSeq("f", Const(b"\x1C"), "f" / Prefixed(DerLengthInt, Struct(
        "issuing_member_state"  / FocusedSeq("f", Const(b"\x00"), "f" / C40(Bytes(2))),
        "full_name"             / FocusedSeq("f", Const(b"\x01"), "f" / Prefixed(DerLengthInt, C40(GreedyBytes))),
        "surname_at_birth"      / FocusedSeq("f", Const(b"\x02"), "f" / Prefixed(DerLengthInt, C40(GreedyBytes))),
        "date_of_birth"         / FocusedSeq("f", Const(b"\x03"), "f" / Date(Bytes(3))),
        "country_and_pob"       / FocusedSeq("f", Const(b"\x04"), "f" / Prefixed(DerLengthInt, C40(GreedyBytes))),
        "sex"                   / FocusedSeq("f", Const(b"\x05"), "f" / Bytes(1)),
        "nationality"           / FocusedSeq("f", Const(b"\x06"), "f" / Prefixed(DerLengthInt, C40(GreedyBytes))),
        "nationality_at_birth"  / FocusedSeq("f", Const(b"\x07"), "f" / Prefixed(DerLengthInt, C40(GreedyBytes))),
        "photo"                 / Optional(FocusedSeq("f", Const(b"\x1F"), "f" / Prefixed(DerLengthInt, GreedyBytes)))
    )))

    # IDB Content Structure
    idb1_content = Struct(
        "signable" / RawCopy(Struct(
            "header" / Struct (
                "country_identifier"      / C40(Bytes(2)),
                "signature_algorithm"     / If(this._._._.flags.signed, Enum(Byte, **dict((j,i) for (i,j) in enumerate(SIGNING_ALGOS.keys())))),
                "certificate_reference"   / If(this._._._.flags.signed, Bytes(5)),
                                            If(this._._._.flags.signed, Const(b"\x00")), # Date mask, no unknown fields
                "signature_creation_date" / If(this._._._.flags.signed, Date(Bytes(3)))
            ),
                
            Const(b"\x61"), # Message start
            "message" / Prefixed(DerLengthInt, Struct(
                "mrz_td1"   / Optional(msg_mrz_td1),
                "mrz_td3"   / Optional(msg_mrz_td3),
                "can"       / Optional(msg_can),
                "photo"     / Optional(msg_photo),
                "eu_visa"   / Optional(msg_eu_visa)
            )),
        )),
        "signer_certificate"    / Optional(If(this._.flags.signed, FocusedSeq("sc", Const(b"\x7e"), "sc" / Prefixed(DerLengthInt, GreedyBytes)))),
        "signature_data"        / If(this._.flags.signed, FocusedSeq(
            "sig", Const(b"\x7f"), "sig" / Prefixed(DerLengthInt, Signature(GreedyBytes, this._.signable.data, vk=vk, sk=sk))
        ))
    )

    # IDB1 Outer Structure
    return Struct(
                      Const(b"NDB1"), # IDB Version 1 Magic Number
        "flags"     / FlagsEnum(
                        ExprAdapter(Byte, obj_ - 0x41, obj_ + 0x41),
                        signed = 1,
                        compressed = 2),
        "content"   / IfThenElse(
                        this.flags.compressed, 
                        Base32(Compressed(idb1_content, "zlib", level=9)), 
                        Base32(idb1_content))
    )

def parse(barcode, vk=None):
    if vk is not None:
        try:
            vk = VerifyingKey.from_der(vk)
        except Exception as e:
            raise Exception("Invalid ECDSA public key (DER format expected)") from e

    def clean_json(obj: dict):
        out = dict()
        for k, v in obj.items():
            if isinstance(v, dict):
                # When using RawCopy, the value is wrapped in a dict with offset
                # information, we want to unwrap it for better readability.
                if "offset1" in v and "offset2" in v:
                    out[k] = clean_json(v["value"])
                else:
                    out[k] = clean_json(v)
            else:
                if v is not None and v is not False and not k.startswith("_"):
                    out[k] = v
        return out
    return clean_json(make_idb1(vk=vk).parse(barcode))

def build(obj, sk=None, vk=None, includeCert=False):
    obj["content"]["signable"]["value"]["header"]["certificate_reference"] = None
    obj["content"]["signable"]["value"]["header"]["signature_creation_date"] = None
    obj["content"]["signer_certificate"] = None
    obj["content"]["signature_data"] = None

    if obj["flags"]["signed"] is True:
        rawCert = vk

        if sk is None:
            raise Exception("Unspecified signing key")
        if vk is None:
            raise Exception("Unspecified public signer certificate")
        
        if includeCert:
            obj["content"]["signer_certificate"] = rawCert

        try:
            sk = SigningKey.from_der(sk)
        except Exception as e:
            raise Exception("Invalid ECDSA signing key (DER format expected)") from e
        if sk.curve.baselen < 32:
            raise Exception("Unsupported signing key size (at least 256 bits expected)")

        try:
            vk = VerifyingKey.from_der(vk)
        except Exception as e:
            raise Exception("Invalid ECDSA public certificate (DER format expected)") from e
        
        hashfunc = SIGNING_ALGOS[obj["content"]["signable"]["value"]["header"]["signature_algorithm"]]
        sk.default_hashfunc = hashfunc
        vk.default_hashfunc = hashfunc

        obj["content"]["signable"]["value"]["header"]["certificate_reference"] = sha1(rawCert).digest()[-5:]
        obj["content"]["signable"]["value"]["header"]["signature_creation_date"] = int(datetime.now().strftime("%m%d%Y")).to_bytes(3)
    return make_idb1(sk=sk, vk=vk).build(obj)
