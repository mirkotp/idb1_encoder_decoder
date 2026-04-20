from idb1.parser import parse
import streamlit as st
from hashlib import sha256, sha384, sha512
import cv2
import numpy as np
from PIL import Image, ImageOps
from ecdsa import VerifyingKey
import pandas as pd

SIGNING_ALGOS = dict(ecdsa_sha256=sha256, ecdsa_sha384=sha384, ecdsa_sha512=sha512)

st.set_page_config(layout="centered", page_title="Barcode Reader Demo", page_icon="🤳🏻")
st.title("✨ IDB Barcode Reader 🤳🏻", text_alignment="center")

sc1, sc2 = st.columns(2)
with sc1:
    barcode = st.file_uploader("Upload Barcode Image", type=["png", "jpg", "jpeg"], accept_multiple_files=False)
with sc2:
    certificate = st.file_uploader("Upload Signer Certificate (DER format)", type=["der"], accept_multiple_files=False)

if barcode is None:
    st.info("Load a barcode image")
    st.stop()

# Load image and convert image
try:
    image = Image.open(barcode).convert("RGB")
    image = ImageOps.expand(image, border=30, fill="white")
    image = np.array(image)[:, :, ::-1].copy()
    image = cv2.cvtColor(image, cv2.COLOR_BGR2GRAY)
except Exception as e:
    st.error("Failed to load the image. Please make sure it's a valid image file.")
    st.stop()
    
# Detect and read QR Code
detector = cv2.QRCodeDetector()
data, points, _ = detector.detectAndDecode(image)
if points is None:
    st.error("No barcode detected in the uploaded image.")
    st.stop()

# Decode barcode content
try:
    parsed = parse(data.encode())
except Exception as e:
    st.error(f"Failed to parse the decoded data: {e}")
    st.stop()

# Preload known barcode fields
b_content = parsed["content"]
b_flags = parsed["flags"]
b_signed = b_flags["signed"] if "signed" in b_flags else None
b_compressed = b_flags["compressed"] if "compressed" in b_flags else None

b_signable = b_content["signable"]
b_header = b_signable["header"]
b_message = b_signable["message"]
b_raw_data = b_signable["raw_data"]

b_signer_certificate = b_content["signer_certificate"] if "signer_certificate" in b_content else None
b_signature_data = b_content["signature_data"] if "signature_data" in b_content else None

b_idb_version = 1,
b_country_identifier = b_header["country_identifier"]

b_signature_algorithm = b_header["signature_algorithm"] if "signature_algorithm" in b_header else None
b_certificate_reference = b_header["certificate_reference"] if "certificate_reference" in b_header else None
b_signature_creation_date = b_header["signature_creation_date"] if "signature_creation_date" in b_header else None

b_euvisa = b_message["eu_visa"]
b_euvisa_issuing_member_state = b_euvisa["issuing_member_state"] if "issuing_member_state" in b_euvisa else ""
b_euvisa_full_name = b_euvisa["full_name"] if "full_name" in b_euvisa else ""
b_euvisa_surname_at_birth = b_euvisa["surname_at_birth"] if "surname_at_birth" in b_euvisa else ""
b_euvisa_date_of_birth = b_euvisa["date_of_birth"] if "date_of_birth" in b_euvisa else ""
b_euvisa_country_of_birth = b_euvisa["country_of_birth"] if "country_of_birth" in b_euvisa else ""
b_euvisa_place_of_birth = b_euvisa["place_of_birth"] if "place_of_birth" in b_euvisa else ""
b_euvisa_sex = b_euvisa["sex"].decode() if "sex" in b_euvisa else ""
b_euvisa_nationality = b_euvisa["nationality"] if "nationality" in b_euvisa else ""
b_euvisa_nationality_at_birth = b_euvisa["nationality_at_birth"] if "nationality_at_birth" in b_euvisa else ""
b_euvisa_photo = b_euvisa["photo"] if "photo" in b_euvisa else None

# Display cerficate contents
st.markdown("#### EU Visa")        

eu_visa = pd.DataFrame({
    "Issuing Member State": b_euvisa_issuing_member_state,
    "Full Name": b_euvisa_full_name,
    "Surname at Birth": b_euvisa_surname_at_birth,
    "Date of Birth": b_euvisa_date_of_birth,
    "Country of Birth": b_euvisa_country_of_birth,
    "Place of Birth": b_euvisa_place_of_birth,
    "Sex": b_euvisa_sex,
    "Nationality": b_euvisa_nationality,
    "Nationality at Birth": b_euvisa_nationality_at_birth,
}, index=[0])

sc1, sc2 = st.columns([3,2])
with sc1:
    st.table(eu_visa.T, hide_header=True)
with sc2:
    if b_euvisa_photo:
        st.image(b_euvisa_photo)
    if b_signed:
        if certificate is None and b_signer_certificate is None:
            st.warning("⚠️ The barcode is signed but there is no certifica (neither uploaded nor embedded in the barcode) to verify the signature against.")
        else:
            if b_signature_data is None:
                st.error("❌ The barcode is supposed to be signed but no signature was found.")
            else:
                if b_signer_certificate:
                    try:
                        vk = VerifyingKey.from_der(b_signer_certificate)
                        try:
                            vk.verify(b_signature_data, b_raw_data, hashfunc=SIGNING_ALGOS[b_signature_algorithm])
                            st.success("✅ Valid signature (verified with barcode embedded certificate).")
                        except Exception as e:
                            st.error(f"❌ Signature verification failed (verified with barcode embedded certificate).")
                    except:
                        st.error("❌ Invalid certificate: The certificate embedded in the barcode is not a valid DER-encoded ECDSA certificate.")
                if certificate:
                    try:
                        vk = VerifyingKey.from_der(certificate.getvalue())
                        try:
                            vk.verify(b_signature_data, b_raw_data, hashfunc=SIGNING_ALGOS[b_signature_algorithm])
                            st.success("✅ Valid signature (verified with uploaded certificate).")
                        except Exception as e:
                            st.error("❌ Signature verification failed (verified with uploaded certificate).")
                    except Exception as e:
                        st.error("❌ Invalid certificate: The certificate you uploaded is not a valid DER-encoded ECDSA certificate.")
                else:
                    st.info("ℹ️ Upload a trusted certificate for a secure signature certification.")
    else:
        st.info("ℹ️ This barcode is not cryptographically signed.")

st.markdown("#### Header")
header = pd.DataFrame({
    "IDB Version": b_idb_version,
    "Country Identifier": str(b_country_identifier),
    "Signed": "✔️" if b_signed else "✖️",
    "Compressed": "✔️" if b_compressed else "✖️",
    "Signature Algorithm": b_signature_algorithm if b_signature_algorithm else "-",
    "Certificate Reference": b_certificate_reference.hex() if b_certificate_reference else "-",
    "Signature Creation Date": b_signature_creation_date if b_signature_creation_date else "-",
    "Signature": b_signature_data.hex() if b_signature_data else "-",
    "Certificate": b_signer_certificate.hex() if b_signer_certificate else "-"
})
st.table(header.T, hide_header=True)

st.divider()
with st.expander(f"Raw barcode data ({len(data)} bytes)", expanded=False):
    st.write(data)
    st.markdown("##### Decoded barcode")
    st.json(parsed, expanded=True)