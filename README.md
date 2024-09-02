# idb1_encoder_decoder

A simple Encoder/Decoder for ICAO Datastructure for Barcode.

## Installation

```$ pip install git+https://github.com/mirkotp/idb1_encoder_decoder```

## Development

Clone the source and install the package in "editable mode", by running the following command from the root directory of the project:

```$ pip install -e .```

In this way, running the program (check [Usage](#usage)) will reflect any changes made to the source files.

## Usage

```$ idb1 [--secret FILE] [--public FILE] <enc|dec> input_file```

The idb1 commands consist of two sub-commands, ```enc``` and ```dec```, for encoding and deconding a barcode respectively. Both require an ```input_file``` which can be provided as a positional argoment or though piping or redirect. These commands will all work:

```$ idb1 <enc|dec> < input_file```

```$ cat input_file | idb1 <enc|dec>```

```$ echo some input | idb1 <enc|dec>```

### Decoding

When decoding, the expected input is an encoded barcode, for example

```$ echo NDB1CPDNLW6JUSGGZGRLBWPNXEAAWXEB5G | idb1 dec```

will output the contents of the barcode:

```
compressed = True
country_identifier = UTO
can = 156782
```

### Encoding

When encoding, the expected input is a ```key=value``` configuration file. Currently the following properties are supported:

```
compressed = [True | False]
signed = [True | False]
signature_algorithm = [required if signed = True, possible values: ecdsa_sha256, ecdsa_sha384, ecdsa_sha512]
country_identifier = [required, 3 alphabetic characters string]
mrz_td1 = [60 alphanumeric characters string]
mrz_td3 = [60 alphanumeric characters string]
can = [6 numeric characters string]
photo = [relative path, to current working dir, to image file which will be embedded as a bytes blob into the barcode]
```

As an example, specular to what we did with decoding, suppose we have the following ```barcode.txt```:

```
compressed = True
country_identifier = UTO
can = 156782
```

Then, ```$ idb1 enc barcode.txt``` will output ```NDB1CPDNLW6JUSGGZGRLBWPNXEAAWXEB5G```.

### Encode a signed barcode

When encoding a barcode with ```signed = True``` option, it is necessary that you specify the secret key (```--secret``` option) and the corresponding public signer certificate (```--public``` option), both as a DER file.

The public signer certificate can be included into the barcode by using the ```--include_cert``` option.

Example:

```
$ idb1 enc --secret examples/cert/secret.der --public examples/cert/public.der --include-cert < ex
amples/barcode_signed.txt

NDB1B3HCQF2XQUQVL4MDYGAYH5LOIMEDASBBAWNDKO7SYGBLDAEAGA4VIMSGOHUBACBQFFOAQIAAKANBAABAN35CNLPI6VN3LPTX4WYIUYSN2R5EJHHZWX4BHQTTSAIJ5JFUAJJJ4IJZ7NLC7CG3FHX3Q62MUPOEBLC2MT63ZE3JDIYJ2F2XQUQVL472AEGEYWVSKZCIZHW7EZNVH42JE2VOJIELM7IJWZKTZEFLPXY2U73DCMER2PZDF7OBMVFPKMM6PDALC33RE6RE75V2DRYOXFTWMNNRA7EA
```

Normally the signature scheme is non-deterministic so the barcode changes every time you run the command.

### Verify a signed barcode

When decoding a signed barcode, you can use the ```--public``` option to specify a public signer certificate to be used to verify the signature. This will output the result the validation.

If no certificate is specified, the barcode will still be decoded but you will receive a warning stating that the signature canìt be verified.

Example:

```
$ echo NDB1B3HCQF2XQUQVL4MDYGAYH5LOIMEDASBBAWNDKO7SYGBLDAEAGA4VIMSGOHUBACBQFFOAQIAAKANBAABAN35CNLPI6VN3LPTX4WYIUYSN2R5EJHHZWX4BHQTTSAIJ5JFUAJJJ4IJZ7NLC7CG3FHX3Q62MUPOEBLC2MT63ZE3JDIYJ2F2XQUQVL472APQBUDU5MVXZJXMO6RLRBGIZHKB4EO7NWGQ5UY2EFMVQC5DVN4UE7ZSNYG4WBKE6FTHXFAO33H3IV4EFZ2NC7ATZNUD66QWE2KHF5MUI | idb1 dec --public examples/cert/public.der 

>>>>>>>>> SIGNATURE: valid
signed = True
country_identifier = UTO
signature_algorithm = ecdsa_sha512
certificate_reference = b'\xea\xf0\xa4*\xbe'
signature_creation_date = 2024-08-30
can = 156782
signer_certificate = b"0V0\x10\x06\x07*\x86H\xce=\x02\x01\x06\x05+\x81\x04\x00\n\x03B\x00\x04\r\xdfD\xd5\xbd\x1e\xabv\xb7\xce\xfc\xb6\x11LI\xba\x8fH\x93\x9f6\xbf\x02xNr\x02\x13\xd4\x96\x80JS\xc4'?j\xc5\xf1\x1be=\xf7\x0fi\x94{\x88\x15\x8bL\x9f\xb7\x92m#F\x13\xa2\xea\xf0\xa4*\xbe"
signature_data = b"|\x03A\xd3\xac\xad\xf2\x9b\xb1\xde\x8a\xe2\x13#'PxG}\xb64;Lh\x85e`.\x8e\xad\xe5\t\xfc\xc9\xb87,\x15\x13\xc5\x99\xeeP;{>\xd1^\x10\xb9\xd3E\xf0O-\xa0\xfd\xe8X\x9aQ\xcb\xd6Q"
```

## Caveats

Input validation and exception management are still under development. Errors usually mean the input is not well-formed: reading the exceptions can give some clue about what's wrong.  
Sometimes the problem is that you are running the command for encoding when in reality you meant to decode, or viceversa.

## Examples

The [_examples_](./examples) directory contains ready-to-use configuration for a few sample barcodes. 

In [_examples/cert_](./examples/cert) there is a pair of DER files for testing with signed barcodes. The example signer certificate is not compliant with the IDB specification, but it should be good enough for testing purpose.