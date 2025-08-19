document.addEventListener('DOMContentLoaded', () => {
    // --- DOM ELEMENT REFERENCES ---
    const plaintextEl = document.getElementById('plaintext');
    const hillKeyEncEl = document.getElementById('hill-key-enc');
    const sdesKeyEncEl = document.getElementById('sdes-key-enc');
    const coverImageUploadEl = document.getElementById('cover-image-upload');
    const coverFileNameEl = document.getElementById('cover-file-name');
    const encryptBtn = document.getElementById('encrypt-btn');
    const stegoImageContainer = document.getElementById('stego-image-container');
    const stegoImagePreview = document.getElementById('stego-image-preview');
    const downloadStegoImageLink = document.getElementById('download-stego-image');

    const stegoImageUploadEl = document.getElementById('stego-image-upload');
    const stegoFileNameEl = document.getElementById('stego-file-name');
    const hillKeyDecEl = document.getElementById('hill-key-dec');
    const sdesKeyDecEl = document.getElementById('sdes-key-dec');
    const decryptBtn = document.getElementById('decrypt-btn');
    const resultContainer = document.getElementById('result-container');
    const decryptedTextEl = document.getElementById('decrypted-text');
    
    const canvas = document.getElementById('image-canvas');
    const ctx = canvas.getContext('2d');

    const logContentEl = document.getElementById('log-content');
    const clearLogBtn = document.getElementById('clear-log-btn');

    // --- LOGGING UTILITY ---
    const log = (message, type = 'info') => {
        const p = document.createElement('p');
        p.className = `log-message ${type}`;
        p.textContent = `[${new Date().toLocaleTimeString()}] ${message}`;
        logContentEl.appendChild(p);
        logContentEl.scrollTop = logContentEl.scrollHeight;
    };

    clearLogBtn.addEventListener('click', () => {
        logContentEl.innerHTML = '';
        log('Log cleared.');
    });

    // --- HILL CIPHER MODULE ---
    const HillCipher = (() => {
        const modInverse = (a, m) => {
            a = ((a % m) + m) % m;
            for (let x = 1; x < m; x++) {
                if ((a * x) % m === 1) return x;
            }
            return null;
        };

        const getDeterminant = (m) => (m[0][0] * m[1][1] - m[0][1] * m[1][0]);

        const isKeyValid = (key) => {
            const det = getDeterminant(key);
            return modInverse(det, 26) !== null;
        };

        const getInvertedKey = (key) => {
            const det = getDeterminant(key);
            const detInv = modInverse(det, 26);
            if (detInv === null) throw new Error('Key matrix is not invertible.');
            
            const adj = [
                [key[1][1], -key[0][1]],
                [-key[1][0], key[0][0]]
            ];

            return adj.map(row => row.map(val => (val * detInv % 26 + 26) % 26));
        };

        const crypt = (text, key) => {
            let result = '';
            for (let i = 0; i < text.length; i += 2) {
                const p1 = text.charCodeAt(i) - 65;
                const p2 = text.charCodeAt(i + 1) - 65;
                const c1 = (p1 * key[0][0] + p2 * key[1][0]) % 26;
                const c2 = (p1 * key[0][1] + p2 * key[1][1]) % 26;
                result += String.fromCharCode(c1 + 65) + String.fromCharCode(c2 + 65);
            }
            return result;
        };

        return {
            encrypt: (plaintext, key) => {
                let text = plaintext.toUpperCase().replace(/[^A-Z]/g, '');
                if (text.length % 2 !== 0) text += 'X';
                return crypt(text, key);
            },
            decrypt: (ciphertext, key) => {
                const invKey = getInvertedKey(key);
                return crypt(ciphertext, invKey);
            },
            parseKey: (keyString) => {
                const nums = keyString.trim().split(/\s+/).map(Number);
                if (nums.length !== 4 || nums.some(isNaN)) throw new Error('Invalid Hill key format.');
                const key = [[nums[0], nums[1]], [nums[2], nums[3]]];
                if (!isKeyValid(key)) throw new Error('Hill key is not invertible mod 26.');
                return key;
            }
        };
    })();

    // --- SDES MODULE ---
    const SDES = (() => {
        const P10 = [3, 5, 2, 7, 4, 10, 1, 9, 8, 6];
        const P8  = [6, 3, 7, 4, 8, 5, 10, 9];
        const IP  = [2, 6, 3, 1, 4, 8, 5, 7];
        const IP_INV = [4, 1, 3, 5, 7, 2, 8, 6];
        const EP  = [4, 1, 2, 3, 2, 3, 4, 1];
        const P4  = [2, 4, 3, 1];
        const S0  = [[1, 0, 3, 2], [3, 2, 1, 0], [0, 2, 1, 3], [3, 1, 3, 2]];
        const S1  = [[0, 1, 2, 3], [2, 0, 1, 3], [3, 0, 1, 0], [2, 1, 0, 3]];

        const permute = (bits, table) => table.map(i => bits[i - 1]).join('');
        const shift = (bits) => bits.substring(1) + bits[0];
        
        const generateKeys = (key) => {
            let p10 = permute(key, P10);
            let ls1 = shift(p10.substring(0, 5)) + shift(p10.substring(5));
            const k1 = permute(ls1, P8);
            let ls2 = shift(shift(ls1.substring(0, 5))) + shift(shift(ls1.substring(5)));
            const k2 = permute(ls2, P8);
            return [k1, k2];
        };

        const fk = (bits, subkey) => {
            const [left, right] = [bits.substring(0, 4), bits.substring(4)];
            const ep = permute(right, EP);
            const xor = (parseInt(ep, 2) ^ parseInt(subkey, 2)).toString(2).padStart(8, '0');
            const s0_row = parseInt(xor[0] + xor[3], 2), s0_col = parseInt(xor[1] + xor[2], 2);
            const s1_row = parseInt(xor[4] + xor[7], 2), s1_col = parseInt(xor[5] + xor[6], 2);
            const s_out = S0[s0_row][s0_col].toString(2).padStart(2, '0') + S1[s1_row][s1_col].toString(2).padStart(2, '0');
            const p4 = permute(s_out, P4);
            return (parseInt(left, 2) ^ parseInt(p4, 2)).toString(2).padStart(4, '0') + right;
        };

        const crypt = (bits, k1, k2) => {
            let ip = permute(bits, IP);
            let fk1 = fk(ip, k1);
            let swapped = fk1.substring(4) + fk1.substring(0, 4);
            let fk2 = fk(swapped, k2);
            return permute(fk2, IP_INV);
        };

        return {
            encrypt: (char, key) => {
                const [k1, k2] = generateKeys(key);
                const bits = char.charCodeAt(0).toString(2).padStart(8, '0');
                const encryptedBits = crypt(bits, k1, k2);
                return String.fromCharCode(parseInt(encryptedBits, 2));
            },
            decrypt: (char, key) => {
                const [k1, k2] = generateKeys(key);
                const bits = char.charCodeAt(0).toString(2).padStart(8, '0');
                const decryptedBits = crypt(bits, k2, k1); // Key order reversed
                return String.fromCharCode(parseInt(decryptedBits, 2));
            }
        };
    })();

    // --- STEGANOGRAPHY MODULE (LSB) ---
    const Steganography = (() => {
        const DELIMITER = "00000000"; // Null byte delimiter

        const hide = (message) => {
            const messageBits = message.split('').map(c => c.charCodeAt(0).toString(2).padStart(8, '0')).join('') + DELIMITER;
            log(`Message bitstream length (with delimiter): ${messageBits.length}`, 'step');

            const imageData = ctx.getImageData(0, 0, canvas.width, canvas.height);
            const pixels = imageData.data;

            if (messageBits.length > pixels.length / 4 * 3) {
                throw new Error("Message is too large for this image.");
            }

            let dataIndex = 0;
            for (let i = 0; i < pixels.length && dataIndex < messageBits.length; i += 4) {
                // R, G, B channels. Alpha (i+3) is ignored.
                for (let j = 0; j < 3 && dataIndex < messageBits.length; j++) {
                    pixels[i + j] = (pixels[i + j] & 0xFE) | parseInt(messageBits[dataIndex], 2);
                    dataIndex++;
                }
            }
            ctx.putImageData(imageData, 0, 0);
            log('Message successfully embedded into image canvas.', 'success');
            return canvas.toDataURL('image/png');
        };

        const extract = () => {
            const imageData = ctx.getImageData(0, 0, canvas.width, canvas.height);
            const pixels = imageData.data;
            let extractedBits = "";
            let message = "";

            for (let i = 0; i < pixels.length; i += 4) {
                for (let j = 0; j < 3; j++) {
                    extractedBits += (pixels[i + j] & 1);
                    if (extractedBits.length === 8) {
                        if (extractedBits === DELIMITER) {
                            log('Delimiter found. Message extraction complete.', 'success');
                            return message;
                        }
                        message += String.fromCharCode(parseInt(extractedBits, 2));
                        extractedBits = "";
                    }
                }
            }
            log('Reached end of image without finding a delimiter.', 'error');
            return message; // Return what was found, might be partial/corrupt
        };
        
        return { hide, extract };
    })();

    // --- EVENT LISTENERS ---
    coverImageUploadEl.addEventListener('change', (e) => {
        const file = e.target.files[0];
        if (file) {
            coverFileNameEl.textContent = file.name;
            log(`Cover image selected: ${file.name}`);
        }
    });

    stegoImageUploadEl.addEventListener('change', (e) => {
        const file = e.target.files[0];
        if (file) {
            stegoFileNameEl.textContent = file.name;
            log(`Stego-image selected: ${file.name}`);
        }
    });

    encryptBtn.addEventListener('click', () => {
        try {
            // 1. Get and Validate Inputs
            const plaintext = plaintextEl.value;
            const hillKeyStr = hillKeyEncEl.value;
            const sdesKey = sdesKeyEncEl.value;
            const coverFile = coverImageUploadEl.files[0];

            if (!plaintext || !hillKeyStr || !sdesKey || !coverFile) {
                throw new Error("All fields in the encryption panel are required.");
            }
            if (sdesKey.length !== 10 || !/^[01]+$/.test(sdesKey)) {
                throw new Error("SDES key must be 10 bits.");
            }
            log('Inputs validated.');

            // 2. Hill Cipher Encryption
            const hillKey = HillCipher.parseKey(hillKeyStr);
            log('Hill Cipher key is valid.', 'step');
            const hillCiphertext = HillCipher.encrypt(plaintext, hillKey);
            log(`Hill Cipher Output: ${hillCiphertext}`, 'step');

            // 3. SDES Encryption
            let sdesCiphertext = "";
            for (const char of hillCiphertext) {
                sdesCiphertext += SDES.encrypt(char, sdesKey);
            }
            log(`SDES Ciphertext (raw): ${sdesCiphertext}`, 'step');

            // 4. Steganography
            const reader = new FileReader();
            reader.onload = (e) => {
                const img = new Image();
                img.onload = () => {
                    canvas.width = img.width;
                    canvas.height = img.height;
                    ctx.drawImage(img, 0, 0);
                    try {
                        const stegoDataUrl = Steganography.hide(sdesCiphertext);
                        stegoImagePreview.src = stegoDataUrl;
                        downloadStegoImageLink.href = stegoDataUrl;
                        downloadStegoImageLink.download = 'stego-image.png';
                        stegoImageContainer.style.display = 'block';
                        log('Encryption and hiding process complete!', 'success');
                    } catch (err) {
                        log(err.message, 'error');
                    }
                };
                img.src = e.target.result;
            };
            reader.readAsDataURL(coverFile);

        } catch (err) {
            log(err.message, 'error');
        }
    });

    decryptBtn.addEventListener('click', () => {
        try {
            // 1. Get and Validate Inputs
            const stegoFile = stegoImageUploadEl.files[0];
            const hillKeyStr = hillKeyDecEl.value;
            const sdesKey = sdesKeyDecEl.value;

            if (!stegoFile || !hillKeyStr || !sdesKey) {
                throw new Error("All fields in the decryption panel are required.");
            }
            if (sdesKey.length !== 10 || !/^[01]+$/.test(sdesKey)) {
                throw new Error("SDES key must be 10 bits.");
            }

            // 2. Load image to canvas for extraction
            const reader = new FileReader();
            reader.onload = (e) => {
                const img = new Image();
                img.onload = () => {
                    canvas.width = img.width;
                    canvas.height = img.height;
                    ctx.drawImage(img, 0, 0);
                    try {
                        // 3. Extract hidden message
                        const extractedSdesCiphertext = Steganography.extract();
                        log(`Extracted SDES Ciphertext (raw): ${extractedSdesCiphertext}`, 'step');

                        // 4. SDES Decryption
                        let recoveredHillCiphertext = "";
                        for (const char of extractedSdesCiphertext) {
                            recoveredHillCiphertext += SDES.decrypt(char, sdesKey);
                        }
                        log(`Recovered Hill Ciphertext: ${recoveredHillCiphertext}`, 'step');
                        
                        // 5. Hill Cipher Decryption
                        const hillKey = HillCipher.parseKey(hillKeyStr);
                        const originalPlaintext = HillCipher.decrypt(recoveredHillCiphertext, hillKey);

                        // 6. Display Result
                        decryptedTextEl.textContent = originalPlaintext;
                        resultContainer.style.display = 'block';
                        log('Decryption and extraction process complete!', 'success');

                    } catch (err) {
                        log(err.message, 'error');
                    }
                };
                img.src = e.target.result;
            };
            reader.readAsDataURL(stegoFile);

        } catch (err) {
            log(err.message, 'error');
        }
    });
});
