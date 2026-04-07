from idb1.parser import build, parse
import streamlit as st
import qrcode
from io import BytesIO
import re
import subprocess

MEMBER_STATES = ["AUT","BEL","BGR","HRV","CYP","CZE","DNK","EST","FIN","FRA","DEU","GRC","HUN","IRL","ITA","LVA","LTU","LUX","MLT","NLD","POL","PRT","ROU","SVK","SVN","ESP","SWE"]

st.set_page_config(layout="wide")

st.title("🇪🇺 EU Visa IDB Barcode Demo ✨", text_alignment="center")

col1, col2 = st.columns([2, 3])

with col1:
    st.header("Input Data", divider="blue")
    st.subheader("Header")

    country_identifier = st.selectbox("Country Identifier", options=MEMBER_STATES)

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
    visa_issuing_member_state = st.selectbox("Issuing Member State", options=MEMBER_STATES, index=MEMBER_STATES.index(country_identifier), disabled=True)           
    visa_holder_full_name = st.text_input("Holder full name", value="Some Person")
    visa_holder_surname_at_birth = st.text_input("Holder surname at birth", value="Person")
    visa_date_of_birth = st.date_input("Date of birth", value="1990-01-01", max_value=None, min_value="1890-01-01")
    visa_country_and_pob = st.text_input("Country and Place of Birth", value="Rio de Janeiro Brazil")

    sex_labels = { "M": "Male", "F": "Female", "X": "Unspecified" }
    visa_sex = st.selectbox("Sex", options=sex_labels.keys(), format_func=lambda x: sex_labels[x], index=0)

    nationality = st.text_input("Nationality", value="Argentinian")
    nationality_at_birth = st.text_input("Nationality at Birth", value="Brazilian")
    visa_photo = st.file_uploader("Photo", accept_multiple_files=False)

    if visa_photo:
        try:
            st.image(visa_photo)
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
                                "eu_visa": {
                                    "issuing_member_state": visa_issuing_member_state,
                                    "full_name": visa_holder_full_name.upper() if visa_holder_full_name else "",
                                    "surname_at_birth": visa_holder_surname_at_birth.upper() if visa_holder_surname_at_birth else "",
                                    "date_of_birth": int(visa_date_of_birth.strftime("%m%d%Y")).to_bytes(3) if visa_date_of_birth else None,
                                    "country_and_pob": visa_country_and_pob.upper() if visa_country_and_pob else "",
                                    "sex": visa_sex.encode() if visa_sex else None,
                                    "nationality": nationality.upper() if nationality else None,
                                    "nationality_at_birth": nationality_at_birth.upper() if nationality_at_birth else None,
                                }
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
