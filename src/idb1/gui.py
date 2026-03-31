from idb1.parser import build, parse
import streamlit as st
import qrcode
from io import BytesIO
import re
import subprocess

st.set_page_config(layout="wide")

st.title("🇪🇺 EU Visa IDB Barcode Demo ✨", text_alignment="center")

col1, col2 = st.columns([2, 3])

with col1:
    st.header("Input Data", divider="blue")
    st.subheader("Header")

    country_identifier = st.selectbox("Country Identifier", options= ["AUT","BEL","BGR","HRV","CYP","CZE","DNK","EST","FIN","FRA","DEU","GRC","HUN","IRL","ITA","LVA","LTU","LUX","MLT","NLD","POL","PRT","ROU","SVK","SVN","ESP","SWE"])

    with st.container(border=True):
        compressed = st.checkbox("Compressed", value=False)
        signed = st.checkbox("Signed", value=False)
        cert_included = False
        signing_key = None
        certificate = None
        if signed:
            signing_key = st.file_uploader("Upload ECDSA Signer Private Key (DER format)", type=["der"], accept_multiple_files=False)
            certificate = st.file_uploader("Upload Signer Certificate (DER format)", type=["der"], accept_multiple_files=False)
            signature_algorithm = st.selectbox("Signature Algorithm", options=["ecdsa_sha256", "ecdsa_sha384", "ecdsa_sha512"])
            cert_included = st.checkbox("Include signer certificate in the barcode", value=False)


    st.subheader("Message")
    mrz_td1 = st.text_input("MRZ TD1", value=None)
    if mrz_td1:
        if len(mrz_td1) > 0 and len(mrz_td1) != 90:
            st.error("Invalid MRZ TD1 length")
        if not bool(re.fullmatch(r"[A-Z0-9<]+", mrz_td1)):
            st.error("Invalid characters found")

    mrz_td3 = st.text_input("MRZ TD3", value=None)
    if mrz_td3:
        if len(mrz_td3) > 0 and len(mrz_td3) != 88:
            st.error("Invalid MRZ TD3 length")
        if not bool(re.fullmatch(r"[A-Z0-9<]+", mrz_td3)):
            st.error("Invalid characters found")

    can = st.text_input("CAN", value=None, max_chars=6)
    if can:
        if len(can) > 0 and len(can) != 6:
            st.error("Invalid CAN length")
        if not can.isdigit():
            st.error("CAN must be numeric")

    photo = st.file_uploader("Photo", accept_multiple_files=False)

    if photo:
        try:
            st.image(photo)
        except:
            st.warning("Unrecognised image file format")


with col2:
    st.header("Generated Barcode", divider="red")
    try:      
        data = build({
            "flags": {
                "signed":       signed,
                "compressed":   compressed
            },
            "content": {
                "signable": {
                    "value": {
                        "header": {
                            "country_identifier":       country_identifier,
                            "signature_algorithm":      signature_algorithm if signed else None,
                            "certificate_reference":    None,
                            "signature_creation_date":  None
                        },
                        "message": {
                            "mrz_td1":  mrz_td1 if mrz_td1 else None,
                            "mrz_td3":  mrz_td3 if mrz_td3 else None,
                            "can":      can if can else None,
                            "photo":    photo.getvalue() if photo else None
                        },
                    },
                },
                "signer_certificate":   None,
                "signature_data":       None
            }
        }, 
        signing_key.getvalue() if signing_key else None, 
        certificate.getvalue() if certificate else None, 
        cert_included)

        with st.expander(f"Raw barcode data ({len(data)} bytes)", expanded=False):
            st.write(f"{data.decode()}")
    except Exception as e:
        st.error(str(e))
        data = b""

    subcol1, subcol2 = st.columns(2, gap="xxsmall")

    with subcol1:
        st.subheader("QR Code")

        if data.strip():
            try:
                qr = qrcode.make(data, border=0)
                buf = BytesIO()
                qr.save(buf)
                st.image(buf.getvalue())
            except Exception as e:
                st.error("Too much data")
        else:
            st.write("No barcode data.")
        
        st.subheader("JAB Code")

        if data.strip():
            try:
                result = subprocess.run(
                    ["./bin/jabcodeWriter", "--input", data, "--output", "/dev/stdout", "--color-number", "4"],
                    capture_output=True,
                    check=True
                )

                st.image(result.stdout)
            except Exception as e:
                st.error("Too much data")
        else:
            st.write("No barcode data.")


    with subcol2:
        st.subheader("Decoded data")

        if data.strip():
            try:
                parsed = parse(data, certificate.getvalue() if certificate else None)
                st.json(parsed)
            except Exception as e:
                st.error(str(e))
        else:
            st.write("No barcode data.")

    