# Image Steganography Tool (Python)

A command-line tool that hides secret text messages inside PNG images
using **LSB (Least Significant Bit)** encoding, extracts hidden messages
back out, and includes a basic detection/analysis mode to flag images
that likely contain hidden data.

## What this project demonstrates
- Understanding of steganography vs. cryptography (hiding existence of
  data vs. hiding its content)
- Bit-level manipulation and binary encoding
- Basic steganalysis (detection) thinking — relevant for VAPT/forensics roles
- Simple obfuscation (XOR) layered on top of steganography for extra credit

## How it works (good to know for interviews)

Every pixel in an image is made of Red, Green, Blue values (0–255 each).
Changing only the **last bit** of each value shifts the color by at most
1 out of 255 — completely invisible to the human eye. This tool converts
your secret message into binary and hides one bit per color channel:

```
Original pixel:  R=200 (11001000)  G=150 (10010110)  B=90 (01011010)
Secret bits:            1                 0                1
Modified pixel:  R=201 (11001001)  G=150 (10010110)  B=91 (01011011)
```

A special delimiter (`#####END#####`) marks where the hidden message
ends, so extraction knows when to stop reading.

## Setup

```bash
pip install Pillow
```

## Usage

**Hide a message:**
```bash
python stego_tool.py hide -i cover.png -o secret.png -m "Your secret message"
```

**Hide the contents of a text file:**
```bash
python stego_tool.py hide -i cover.png -o secret.png -f message.txt
```

**Hide a message with password protection (XOR obfuscation):**
```bash
python stego_tool.py hide -i cover.png -o secret.png -m "Top secret" --password "mypass123"
```

**Extract a hidden message:**
```bash
python stego_tool.py extract -i secret.png
python stego_tool.py extract -i secret.png --password "mypass123"   # if password was used
```

**Analyze an image for likely hidden data (detection mode):**
```bash
python stego_tool.py analyze -i secret.png
```

## Important notes
- **Use PNG images only.** JPEG uses lossy compression, which destroys
  LSB data. Always save cover/output images as PNG.
- Larger images can hide more data — a 500×500 image can hold roughly
  90,000 characters at maximum capacity (in practice, keep messages
  well under that for reliability).
- The password feature uses a simple **XOR cipher** — this is for
  educational demonstration, not production-grade encryption. If you
  want to extend this into a stronger project, combine it with AES
  encryption (encrypt the message first, then hide the ciphertext).

## The "analyze" command — what it actually checks
This is a simplified educational steganalysis check: it measures how
close an image's least-significant-bit distribution is to a random
50/50 split. LSB steganography pushes this ratio close to 50%, so
images noticeably close to that split are flagged as suspicious. It
also attempts a direct extraction to see if the delimiter is present.
Real steganalysis tools (e.g., StegExpose, zsteg) use more advanced
statistical methods — mention this as a known limitation if asked.

## Sample Output
```
✓ Message hidden successfully in 'secret.png'
  Message length: 52 characters
  Image capacity used: 0.43%

✓ Hidden message found:

This is a secret cybersecurity project test message!
```

## Resume Bullet
> "Built a Python steganography tool implementing LSB (Least Significant
> Bit) encoding to embed and extract hidden text within PNG images;
> added password-based XOR obfuscation and a basic statistical
> steganalysis module to detect likely LSB-modified images."

## Possible Extensions
- Replace XOR with real AES encryption (via the `cryptography` library)
  before hiding the message
- Support hiding files/images inside images, not just text
- Build a simple GUI (Tkinter) or web frontend for drag-and-drop use
- Add audio-file steganography (hide data in .wav files) as a bonus module
