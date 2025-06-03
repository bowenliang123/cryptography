# Cryptography - Encryption, Decryption, Hashing for Files and Text

**Author:** [bowenliang123](https://github.com/bowenliang123)

**Github Repository:** https://github.com/bowenliang123/dify-plugin-crypto

**Dify Marketplace:** https://marketplace.dify.ai/plugins/bowenliang123/crypto

## Description

This Dify plugin `crypto` provides tools for Encryption, Decryption, Hashing with [Cryptography](https://cryptography.io/).

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

## Changelog

- 0.0.1:
  - Introduce `sha256sum` and `md5sum` tools for hashing the input binary file
  - Introduce `rsa_encrypt` and `rsa_decrypt` tools for RSA encryption and decryption of Base64 format ciphertext

## License

- Apache License 2.0

## Privacy

This plugin collects no data.

All the cryptography operations are completed locally. NO data is transmitted to third-party services.
