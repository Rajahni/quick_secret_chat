async function encryptString(text, key) {
    const encoder = new TextEncoder();
    const data = encoder.encode(text);
    
    // Generate a key from the password
    const keyMaterial = await window.crypto.subtle.importKey(
        "raw",
        encoder.encode(key),
        "PBKDF2",
        false,
        ["deriveBits", "deriveKey"]
    );
    
    // Generate a random salt
    const salt = window.crypto.getRandomValues(new Uint8Array(16));
    
    // Derive the key using PBKDF2
    const cryptoKey = await window.crypto.subtle.deriveKey(
        {
            name: "PBKDF2",
            salt: salt,
            iterations: 100000,
            hash: "SHA-256"
        },
        keyMaterial,
        { name: "AES-CBC", length: 256 },
        false,
        ["encrypt"]
    );
    
    // Generate IV
    const iv = window.crypto.getRandomValues(new Uint8Array(16));
    
    // Encrypt the data
    const encrypted = await window.crypto.subtle.encrypt(
        { name: "AES-CBC", iv: iv },
        cryptoKey,
        data
    );
    
    // Combine salt, IV, and encrypted data
    const encryptedArray = new Uint8Array(encrypted);
    const result = {
        salt: Array.from(salt).map(b => b.toString(16).padStart(2, '0')).join(''),
        iv: Array.from(iv).map(b => b.toString(16).padStart(2, '0')).join(''),
        data: Array.from(new Uint8Array(encrypted)).map(b => b.toString(16).padStart(2, '0')).join('')
    };
    
    return `${result.salt}:${result.iv}:${result.data}`;
}

async function decryptString(encryptedText, key) {
    const [saltHex, ivHex, dataHex] = encryptedText.split(':');
    
    const encoder = new TextEncoder();
    const salt = new Uint8Array(saltHex.match(/.{2}/g).map(byte => parseInt(byte, 16)));
    const iv = new Uint8Array(ivHex.match(/.{2}/g).map(byte => parseInt(byte, 16)));
    const data = new Uint8Array(dataHex.match(/.{2}/g).map(byte => parseInt(byte, 16)));
    
    // Import the key material
    const keyMaterial = await window.crypto.subtle.importKey(
        "raw",
        encoder.encode(key),
        "PBKDF2",
        false,
        ["deriveBits", "deriveKey"]
    );
    
    // Derive the key using PBKDF2
    const cryptoKey = await window.crypto.subtle.deriveKey(
        {
            name: "PBKDF2",
            salt: salt,
            iterations: 100000,
            hash: "SHA-256"
        },
        keyMaterial,
        { name: "AES-CBC", length: 256 },
        false,
        ["decrypt"]
    );
    
    // Decrypt the data
    const decrypted = await window.crypto.subtle.decrypt(
        { name: "AES-CBC", iv: iv },
        cryptoKey,
        data
    );
    
    return new TextDecoder().decode(decrypted);
}