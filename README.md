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

### Verify a signed barcode

When decoding a signed barcode, you can use the ```--public``` option to specify a public signer certificate to be used to verify the signature. This will output the result the validation.

If no certificate is specified, the barcode will still be decoded but you will receive a warning stating that the signature canìt be verified.

## Caveats

Input validation and exception management are still under development. Errors usually mean the input is not well-formed: reading the exceptions can give some clue about what's wrong.  
Sometimes the problem is that you are running the command for encoding when in reality you meant to decode, or viceversa.

## Examples

The [_examples_](./examples) directory contains ready-to-use configuration for a few sample barcodes. In [_examples/cert_](./examples/cert) there is a pair of DER files for testing with signed barcodes.