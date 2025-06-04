# Cryptography - Encryption, Decryption, Hashing for Files and Text

**Author:** [bowenliang123](https://github.com/bowenliang123)

**Github Repository:** https://github.com/bowenliang123/dify-plugin-crypto

**Dify Marketplace:** https://marketplace.dify.ai/plugins/bowenliang123/crypto

## Description

This Dify plugin `cryptography` provides tools for Encryption, Decryption, Hashing with [Cryptography](https://cryptography.io/) library.

## Tools and Usage

### File Hashing with SHA256
  - Tool: `sha256sum`
  - Input: 
    - Binary file
  - Output: 
    - SHA256 hash of the input binary file

### File Hashing with MD5
  - Tool: `md5sum`
  - Input: 
    - Binary file
  - Output: MD5 hash of the input binary file

### RSA KeyPair Generation
  - Tool: `rsa_keygen` 
  - Input: 
    - Key size in bits, default: 2048, allowed values: 1024, 2048, 3072, 4096
  - Output: 
    - RSA public and private keys in PEM format (PKCS8)
      - public key: `public_key.pem`
      - private key: `private_key.pem`

### RSA Encryption
- Tool: `rsa_encrypt`
- Input:
    - plain text
    - RSA public key text (eg. copied from `public_key.pem`)
- Output:
  - text: encrypted ciphertext in Base64 format

### RSA Decryption
- Tool: `rsa_decrypt`
- Input:
    - encrypted ciphertext in Base64 format
    - RSA private key text (eg. copied from `private_key.pem`)
- Output:
    - plain text

### Ed25519 KeyPair Generation
  - Tool: `ed25519_keygen` 
  - Input: 
  - Output: 
    - Ed25519 public and private keys in PEM format (PKCS8)
      - public key: `public_key.pem`
      - private key: `private_key.pem`

### Ed25519 Signing
- Tool: `ed25519_sign`
- Input:
    - plain text
    - Ed25519 private key text (eg. copied from `private_key.pem`)
- Output:
  - signature: Ed25519 signature in Base64 format

### Ed25519 Verification
- Tool: `ed25519_verify`
- Input:
    - plain text
    - Ed25519 Signature in Base64 format
    - Ed25519 public key text (eg. copied from `public_key.pem`)
- Output:
    - `True` if the signature is valid, `False` otherwise

## Changelog

- 0.1.0:
  - Introduce tools to support Ed25519 signing, varification, keypair generation, including `ed25519_keygen`, `ed25519_sign` and `ed25519_verify`

- 0.0.1:
  - Introduce `sha256sum` and `md5sum` tools for hashing the input binary file
  - Introduce `rsa_encrypt` and `rsa_decrypt` tools for RSA encryption and decryption of Base64 format ciphertext

## License

- Apache License 2.0

## Privacy

This plugin collects no data.

All the cryptography operations are completed locally. NO data is transmitted to third-party services.
