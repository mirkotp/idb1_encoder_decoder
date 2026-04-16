from idb1.parser import parse
import streamlit as st
from hashlib import sha256, sha384, sha512
import cv2
import numpy as np
from PIL import Image, ImageOps
from ecdsa import VerifyingKey

SIGNING_ALGOS = dict(ecdsa_sha256=sha256, ecdsa_sha384=sha384, ecdsa_sha512=sha512)

st.set_page_config(layout="centered", page_title="Barcode Reader Demo", page_icon="🤳🏻")
st.title("✨ IDB Barcode Reader 🤳🏻", text_alignment="center")

sc1, sc2 = st.columns(2)
with sc1:
    barcode = st.file_uploader("Upload Barcode Image", type=["png", "jpg", "jpeg"], accept_multiple_files=False)
with sc2:
    certificate = st.file_uploader("Upload Signer Certificate (DER format)", type=["der"], accept_multiple_files=False)

if barcode is not None:
    # Load image
    try:
        image = Image.open(barcode).convert("RGB")
    except Exception as e:
        st.error("Failed to load the image. Please make sure it's a valid image file.")
        st.stop()
        
    image = ImageOps.expand(image, border=30, fill="white")
    image = np.array(image)[:, :, ::-1].copy()
    image = cv2.cvtColor(image, cv2.COLOR_BGR2GRAY)

    # Initialize detector
    detector = cv2.QRCodeDetector()

    # Decode
    data, points, _ = detector.detectAndDecode(image)

    if data:
        try:
            parsed = parse(data.encode())
        except Exception as e:
            st.error("Failed to parse the decoded data.")
            st.stop()

        content = parsed["content"]
        flags = parsed["flags"]

        st.markdown("#### EU Visa")        
        if "signed" in flags and flags["signed"]:
            if "signature_data" not in content:
                st.error("The barcode is supposed to be signed but no signature was found.")
            else:
                signature_algorithm = content["signable"]["header"]["signature_algorithm"]
                if "signer_certificate" in content:
                    vk = VerifyingKey.from_der(content["signer_certificate"])
                    try:
                        vk.verify(content["signature_data"], content["signable"]["raw_data"], hashfunc=SIGNING_ALGOS[signature_algorithm])
                        st.success("✅ Valid signature for embedded certificate.")
                    except e:
                        st.error("Signature verification failed")
                if certificate is not None:
                    vk = VerifyingKey.from_der(certificate.getvalue())
                    try:
                        vk.verify(content["signature_data"], content["signable"]["raw_data"], hashfunc=SIGNING_ALGOS[signature_algorithm])
                        st.success("✅ Valid signature for uploaded certificate.")
                    except e:
                        st.error("Signature verification failed")

        if "eu_visa" in content["signable"]["message"]:
            visa = content["signable"]["message"]["eu_visa"]
            eu_visa = {
                "issuing_member_state": visa["issuing_member_state"] if "issuing_member_state" in visa else "",
                "full_name": visa["full_name"] if "full_name" in visa else "",
                "surname_at_birth": visa["surname_at_birth"] if "surname_at_birth" in visa else "",
                "date_of_birth": visa["date_of_birth"] if "date_of_birth" in visa else "",
                "country_of_birth": visa["country_of_birth"] if "country_of_birth" in visa else "",
                "place_of_birth": visa["place_of_birth"] if "place_of_birth" in visa else "",
                "sex": visa["sex"].decode() if "sex" in visa else "",
                "nationality": visa["nationality"] if "nationality" in visa else "",
                "nationality_at_birth": visa["nationality_at_birth"] if "nationality_at_birth" in visa else "",
            }
        
            if "photo" in visa:
                sc1, sc2 = st.columns([3,2])
                with sc1:
                    st.table({k: v for k, v in eu_visa.items() if v is not None})
                with sc2:
                    st.image(visa["photo"])
            else:
                st.table({k: v for k, v in eu_visa.items() if v is not None})
        else:
            st.warning("No EU Visa found in the barcode's message")
        
        st.markdown("#### Header")
        header = {
            "IDB Version": 1,
            "Country Identifier": content["signable"]["header"]["country_identifier"],
            "Signed": "✔️" if "signed" in flags and flags["signed"] else "✖️",
            "Compressed": "✔️" if "compressed" in flags and flags["compressed"] else "✖️",
            "Signature Algorithm": content["signable"]["header"]["signature_algorithm"] if "signature_algorithm" in content["signable"]["header"] else None,
            "Certificate Reference": content["signable"]["header"]["certificate_reference"].hex() if "certificate_reference" in content["signable"]["header"] else None,
            "Signature Creation Date": content["signable"]["header"]["signature_creation_date"] if "signature_creation_date" in content["signable"]["header"] else None,
            "Signature": content["signature_data"].hex() if "signature_data" in content else None,
            "Certificate": content["signer_certificate"].hex() if "signer_certificate" in content else None
        }
        st.table({k: v for k, v in header.items() if v is not None})
        

        st.divider()
        with st.expander(f"Raw barcode data ({len(data)} bytes)", expanded=False):
            st.write(data)
            st.json(parsed, expanded=True)
    else:
        st.error("No QR code found in the uploaded image.")