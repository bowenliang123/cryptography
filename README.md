# Crypto - Encryption, Decryption, Singing with Cryptography

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

## Changelog

- 0.0.1:
  - Introduce `sha256sum` and `md5sum` tools for hashing the input binary file

## License

- Apache License 2.0

## Privacy

This plugin collects no data.

All the cryptography operations are completed locally. NO data is transmitted to third-party services.
