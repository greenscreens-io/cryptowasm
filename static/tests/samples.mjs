/// BASIC HKDF ---------------------------------------------------------

// create master HKDF KEY
const key = await crypto.subtle.importKey(
  'raw',
  new TextEncoder().encode('initial key '),
  { name: 'HKDF' },
  false,
  ['deriveKey', 'deriveBits']);

// Then, perform the HKDF Extract and Expand
const out = await crypto.subtle.deriveBits(
  {
    name: 'HKDF',
    info: new Uint8Array(),
    salt: crypto.getRandomValues(new Uint8Array(32)),
    hash: 'SHA-256'
  },
  key,
  128);  // 16 bytes
  
 /// ---------------------------------------------------------
 
 
function deriveSecretKey(privateKey, publicKey) {
  return crypto.subtle.deriveKey(
    {
      name: "HKDF",
      salt: publicKey
    },
    privateKey,
    {
      name: "AES-GCM",
      length: 256
    },
    false,
    ["encrypt", "decrypt"]
  );
}

async function agreeSharedSecretKey() {
  // Generate 2 ECDH key pairs: one for Alice and one for Bob
  // In more normal usage, they would generate their key pairs
  // separately and exchange public keys securely
  let alicesKeyPair = await crypto.subtle.generateKey(
    {
      name: "ECDH",
      namedCurve: "P-384"
    },
    true,
    ["deriveKey","deriveBits"]
  );

  let bobsKeyPair = await crypto.subtle.generateKey(
    {
      name: "ECDH",
      namedCurve: "P-384"
    },
    true,
    ["deriveKey", "deriveBits"]
  );

	let sharedSecret = await crypto.subtle.deriveBits(
        { name: "ECDH", public: alicesKeyPair.publicKey },
        bobsKeyPair.privateKey, 
        384 
    );
	
	let sharedSecretKey = await crypto.subtle.importKey(
        "raw", 
        sharedSecret, 
        { name: "HKDF" }, 
        false, 
        ["deriveKey", "deriveBits"]
    );
	
	let derived_key = await crypto.subtle.deriveBits(
        { name: "HKDF", hash: "SHA-256", salt: crypto.getRandomValues(new Uint8Array(32)), info: new Uint8Array([]) }, 
        sharedSecretKey, 
        256
    );
	
	
  // Alice then generates a secret key using her private key and Bob's public key.
  let alicesSecretKey = await deriveSecretKey(alicesKeyPair.privateKey, bobsKeyPair.publicKey);

  // Bob generates the same secret key using his private key and Alice's public key.
  let bobsSecretKey = await deriveSecretKey(bobsKeyPair.privateKey, alicesKeyPair.publicKey);

  // Alice can then use her copy of the secret key to encrypt a message to Bob.
  let encryptButton = document.querySelector(".ecdh .encrypt-button");
  encryptButton.addEventListener("click", () => {
    encrypt(alicesSecretKey);
  });

  // Bob can use his copy to decrypt the message.
  let decryptButton = document.querySelector(".ecdh .decrypt-button");
  decryptButton.addEventListener("click", () => {
    decrypt(bobsSecretKey);
  });
}