# Hybrid-Crypto-Steganography

Overview

Hybrid-Crypto-Steganography Suite is a client-side web application that provides a multi-layered security solution for digital text by integrating classical cryptography, modern encryption, and steganography. The tool runs entirely in the user’s browser, ensuring data privacy by performing all operations locally without transmitting sensitive information over the network.

The encryption process consists of:

Hill Cipher – Classical, matrix-based encryption.

Simplified DES (SDES) – Block cipher for additional computational security.

LSB Steganography – Concealing the encrypted text in an image's pixel data.
Features Layered Encryption Model

Hill Cipher – Matrix-based polygraphic substitution cipher for the first encryption layer.

Simplified DES (SDES) – 8-bit block cipher to increase computational complexity.

LSB Steganography – Conceals ciphertext inside image pixels using the Least Significant Bit technique.
Interactive User Interface

Modern glassmorphism UI with animated backgrounds.

Drag-and-drop file upload support.

Real-time cryptographic key validation to avoid errors.
Privacy by Design

100% client-side architecture – All encryption, decryption, and steganography operations are performed locally via JavaScript.
Technology Stack

Frontend: HTML5

Styling: CSS3 (Flexbox, Grid, Animations)

Core Logic: JavaScript (ES6+)

Browser APIs: File API, Drag & Drop API, Canvas API
Operational Workflow Stage 1: Algebraic Transformation (Hill Cipher)

Converts plaintext into letter blocks.

Applies matrix multiplication for encryption.

Obscures character frequency patterns.
Stage 2: Bit-Level Encryption (SDES)

Takes Hill Cipher output and converts it to 8-bit binary.

Performs permutations and substitutions based on a 10-bit SDES key.
Stage 3: Data Concealment (LSB Steganography)

Converts the final ciphertext into a binary stream.

Embeds bits into RGB pixel values of the cover image.

Produces a visually indistinguishable stego-image.
Decryption follows the reverse sequence using the same keys. Usage Guide Encryption

Input Message: Enter plaintext in the text area.

Provide Keys: Enter:

    Hill Cipher key – 4 numbers (matrix form).

    SDES key – 10-bit binary.

Upload Image: PNG or BMP format (drag-and-drop or file selector).

Execute: Click "Encrypt & Hide".

Download: Save the generated stego-image.
Decryption

Upload Stego-Image: PNG or BMP containing hidden data.

Provide Keys: Same Hill Cipher and SDES keys used for encryption.

Execute: Click "Extract & Decrypt".

View Result: Original plaintext appears in the result area.
