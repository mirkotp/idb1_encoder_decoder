import io

from idb1.parser import build, parse
import streamlit as st
from qrcode import QRCode
from io import BytesIO
import subprocess
from PIL import Image
from deepface import DeepFace
from PIL import Image   

MEMBER_STATES = ["AUT","BEL","BGR","HRV","CYP","CZE","DNK","EST","FIN","FRA","DEU","GRC","HUN","IRL","ITA","LVA","LTU","LUX","MLT","NLD","POL","PRT","ROU","SVK","SVN","ESP","SWE"]

st.set_page_config(layout="wide")

st.title("🇪🇺 EU Visa IDB Barcode Demo ✨", text_alignment="center")

col1, col2 = st.columns([3, 2])

with col1:
    st.header("Input Data", divider="blue")
    tab1, tab2, tab3 = st.tabs(["Header", "EU Visa", "Photo"])
    with tab1:
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

    with tab2:
        st.subheader("EU Visa Data")
        visa_issuing_member_state = st.selectbox("Issuing Member State", options=MEMBER_STATES, index=MEMBER_STATES.index(country_identifier), disabled=True)           
        visa_holder_full_name = st.text_input("Holder full name", value="Some Person")
        visa_holder_surname_at_birth = st.text_input("Holder surname at birth", value="Person")
        visa_date_of_birth = st.date_input("Date of birth", value="1990-01-01", max_value=None, min_value="1890-01-01")
        visa_country_and_pob = st.text_input("Country and Place of Birth", value="Rio de Janeiro Brazil")

        sex_labels = { "M": "Male", "F": "Female", "X": "Unspecified" }
        visa_sex = st.selectbox("Sex", options=sex_labels.keys(), format_func=lambda x: sex_labels[x], index=0)

        nationality = st.text_input("Nationality", value="Argentinian")
        nationality_at_birth = st.text_input("Nationality at Birth", value="Brazilian")
        visa_photo = None
    
    with tab3:
        st.subheader("Photo")
        with st.container(border=True):
            visa_photo_original = st.file_uploader("Face Photograph File", accept_multiple_files=False)
            try:
                try:
                    img = Image.open(visa_photo_original)
                except Exception as e:
                    raise Exception("Invalid image file.") from e
        
                visa_photo = visa_photo_original
                visa_photo_width_scale = st.slider("Width Scale (%)", min_value=1, max_value=100, value=100)

                sc1, sc2, sc3 = st.columns([1, 1, 3])
                with sc1:
                    visa_photo_grayscale = st.checkbox("Grayscale", value=False)
                    if visa_photo_grayscale:
                        img = img.convert("L")
                with sc2:
                    visa_photo_crop = st.checkbox("Crop Face", value=False)
                with sc3:
                    if visa_photo_crop:
                        try:
                            detections = DeepFace.extract_faces(
                                img_path=visa_photo_original,
                            )
                        except Exception as e:
                            raise Exception("No facial features found in this picture.") from e

                        x = detections[0]["facial_area"]["x"]
                        y = detections[0]["facial_area"]["y"]
                        w = detections[0]["facial_area"]["w"]
                        h = detections[0]["facial_area"]["h"]

                        visa_photo_crop_padding = st.slider("Crop Margin (pixels)", min_value=0, max_value=50, value=0)
                        left = max(x - visa_photo_crop_padding, 0)
                        top = max(y - visa_photo_crop_padding, 0)
                        right = x + w + visa_photo_crop_padding
                        bottom = y + h + visa_photo_crop_padding

                        img = img.crop((left, top, right, bottom))

                sc1, sc2 = st.columns([1, 4])
                with sc1:
                    visa_photo_compression_algo = st.selectbox("Compression Algorithm", options=["AVIF", "JPEG", "JPEG2000", "WEBP"], index=0)
                with sc2:
                    visa_photo_avif_quality = st.slider("Compression Quality", min_value=0, max_value=100, value=20)

                st.divider()
                img = img.resize((int(img.width * visa_photo_width_scale / 100), int(img.height * visa_photo_width_scale / 100)))
                sc1, sc2 = st.columns(2)
                with sc1:
                    original = Image.open(visa_photo_original)
                    st.caption(f"**Original**  \n{original.size} pixels  \n{visa_photo_original.size} bytes", text_alignment="center")
                    with st.container(horizontal_alignment="center"):
                        st.image(original)
                with sc2:
                    buffer = io.BytesIO()
                    img.save(buffer, format=visa_photo_compression_algo, quality_mode="rates", quality_layers=[100-visa_photo_avif_quality], no_jp2=True, quality=visa_photo_avif_quality, speed=0) 
                    visa_photo = buffer.getvalue()
                    st.caption(f"**Compressed**  \n{img.size} pixels  \n{buffer.tell()} bytes", text_alignment="center")
                    with st.container(horizontal_alignment="center"):
                        st.image(buffer)
            except Exception as e:
                st.error(str(e))

with col2:
    st.header("Barcode Generation", divider="red")
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

                                    "photo": visa_photo if visa_photo else None
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

    with st.expander(f"Decoded data (JSON)", expanded=False):
        if data.strip():
            try:
                parsed = parse(data, certificate.getvalue() if certificate else None)
                st.json(parsed, expanded=True)
            except Exception as e:
                st.error(str(e))
        else:
            st.write("No barcode data.")

    barcode_type = st.selectbox("Barcode type", options=["QR Code", "JAB Code"])

    with st.container(border=True):
        match barcode_type:
            case "QR Code":
                sc1, sc2 = st.columns(2)
                with sc1:
                    qr_version = st.select_slider("QR Code version", options=["Auto"]+list(range(1, 41)), value="Auto")
                with sc2:
                    error_correction_levels = ["L (7%)", "M (15%)", "Q (25%)", "H (30%)"]
                    qr_error_correction = st.select_slider("QR Code error correction level", options=["L (7%)", "M (15%)", "Q (25%)", "H (30%)"], value="M (15%)")

                if data.strip():
                    try:
                        qr = QRCode(version=(qr_version if qr_version != "Auto" else None), error_correction=error_correction_levels.index(qr_error_correction), border=0)
                        qr.add_data(data)
                        qr.make(fit=False)
                        img = qr.make_image()
                        buf = BytesIO()
                        img.save(buf)
                        
                        with st.container(horizontal_alignment="center"):
                            st.image(buf.getvalue())
                    except Exception as e:
                        st.error("Too much data")
                else:
                    st.write("No barcode data.")
            case "JAB Code":
                sc1, sc2 = st.columns(2)
                with sc1:
                    jab_error_correction = st.slider("Error correction level", min_value=1, max_value=10, value=3, step=1)
                    jab_colors = st.select_slider("Number of colors", options=[4, 8])
                with sc2:
                    symbol_version_vertical = st.select_slider("Symbol version (vertical)", options=["Auto"]+list(range(1, 33)), value="Auto")
                    symbol_version_horizontal = st.select_slider("Symbol version (horizontal)", options=["Auto"]+list(range(1, 33)), value="Auto")
                #jab_multisymbol = st.checkbox("Use multiple symbols", value=False)

                additional_params = []
                error = False
                if (symbol_version_vertical == "Auto" and symbol_version_horizontal == "Auto"):
                    pass
                elif(symbol_version_vertical != "Auto" and symbol_version_horizontal != "Auto"):
                    additional_params.extend(["--symbol-version", str(symbol_version_horizontal), str(symbol_version_vertical)])
                else:
                    st.warning("Both symbol versions (horizontal and vertical) must be set to auto or both must be set to a specific version.")
                    error = True

                if not error:
                    if data.strip():
                        try:
                            command = ["./bin/jabcodeWriter", "--input", data, "--output", "/dev/stdout", "--color-number", str(jab_colors), "--ecc-level", str(jab_error_correction)] + additional_params
                            result = subprocess.run(
                                command,
                                capture_output=True,
                                check=True
                            )

                            with st.container(horizontal_alignment="center"):
                                st.image(result.stdout)
                        except Exception as e:
                            st.error("Too much data.")
                    else:
                        st.write("No barcode data.")
