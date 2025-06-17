# Cryptography - All-in-one Encryption, Decryption, Hashing and Signing

**Author:** [bowenliang123](https://github.com/bowenliang123)

**Github Repository:** https://github.com/bowenliang123/cryptography

**Dify Marketplace:** https://marketplace.dify.ai/plugins/bowenliang123/cryptography

## Description

This Dify plugin `cryptography` provides tools for Encryption, Decryption, Hashing and Signing with [Cryptography](https://cryptography.io/en/stable/) library.

## Tools and Usage


<table>
  <tr>
  	 <th>Category</th>
    <th>Algorithm</th>
    <th>Tools & Features</th>
  </tr>

  <tr>
    <td rowspan="2">Hashing</td>
    <td>SHA256</td>
    <td>
      <div>SHA256 File checksum</div>
      <div>(sha256sum)</div>
    </td>
  </tr>
  <tr>
    <td>MD5</td>
    <td>
      <div>MD5 File checksum</div>
      <div>(md5sum)</div>
    </td>
  </tr>

  <tr>
    <td rowspan="2">Symmetric Encryption</td>
    <td rowspan="2">AES</td>
    <td>
      <div>AES Encryption</div>
      <div>(aes_encrypt)</div>
    </td>
  </tr>
  <tr>
    <td>
      <div>AES Decryption</div>
      <div>(aes_decrypt)</div>
    </td>
  </tr>

  <tr>
    <td rowspan="3">Asymmetric Encryption</td>
    <td rowspan="3">RSA</td>
    <td>
      <div>RSA Keypair Generation</div>
      <div>(rsa_keygen)</div>
    </td>
  </tr>
  <tr>
    <td>
      <div>RSA Encryption</div>
      <div>(rsa_encrypt)</div>
    </td>
  </tr>
  <tr>
    <td>
      <div>RSA Decryption</div>
      <div>(rsa_decrypt)</div>
    </td>
  </tr>

  <tr>
    <td rowspan="3">Signing and Verification</td>
    <td rowspan="3">
      <div>Ed25519</div>
      <div>(using EdDSA and Curve25519)</div>
    </td>
    <td>
      <div>Ed25519 Keypair Generation</div>
      <div>(ed25519_keygen)</div>
    </td>
  </tr>
  <tr>
    <td>
      <div>Ed25519 Encryption</div>
      <div>(ed25519_encrypt)</div>
    </td>
  </tr>
  <tr>
    <td>
      <div>Ed25519 Decryption</div>
      <div>(ed25519_decrypt)</div>
    </td>
  </tr>

</table>


### Hashing

#### File Hashing with SHA256
  - Tool: `sha256sum`
  - Input: 
    - Binary file
  - Output: 
    - SHA256 hash of the input binary file

#### File Hashing with MD5
  - Tool: `md5sum`
  - Input: 
    - Binary file
  - Output: MD5 hash of the input binary file
 
#### Text Hashing with HMAC
  - Tool: `hmac_sign`
  - Input: 
    - Plain text for signature
    - Algorithm: `HMAC-SHA1`, `HMAC-SHA256`
    - Key: Signature Key
  - Output: 
    - Signature Text: HMAC signature text in Hex or Base64 format

### Symmetric Encryption and Decryption

#### AES Encryption
- Tool: `aes_encrypt`
- Input:
    - plain text
    - encryption key text with Base 64 encoded
- Output:
  - text: encrypted ciphertext in Base64 format

#### AES Decryption
- Tool: `aes_decrypt`
- Input:
    - ciphertext: encrypted ciphertext with Base 64 encoded
    - decryption key text with Base 64 encoded
- Output:
    - plain text

### Asymmetric Encryption and Decryption

#### RSA KeyPair Generation
  - Tool: `rsa_keygen` 
  - Input: 
    - Key size in bits, default: 2048, allowed values: 1024, 2048, 3072, 4096
  - Output: 
    - RSA public and private keys in PEM format (PKCS8)
      - public key: `public_key.pem`
      - private key: `private_key.pem`

#### RSA Encryption
- Tool: `rsa_encrypt`
- Input:
    - plain text
    - RSA public key text (eg. copied from `public_key.pem`)
- Output:
  - text: encrypted ciphertext in Base64 format

#### RSA Decryption
- Tool: `rsa_decrypt`
- Input:
    - encrypted ciphertext in Base64 format
    - RSA private key text (eg. copied from `private_key.pem`)
- Output:
    - plain text

### Signing and Verification

### Ed25519 KeyPair Generation
  - Tool: `ed25519_keygen` 
  - Input: 
  - Output: 
    - Ed25519 public and private keys in PEM format (PKCS8)
      - public key: `public_key.pem`
      - private key: `private_key.pem`

#### Ed25519 Signing
- Tool: `ed25519_sign`
- Input:
    - plain text
    - Ed25519 private key text (eg. copied from `private_key.pem`)
- Output:
  - signature: Ed25519 signature text in Base64 format

#### Ed25519 Verification
- Tool: `ed25519_verify`
- Input:
    - plain text
    - Ed25519 signature text in Base64 format
    - Ed25519 public key text (eg. copied from `public_key.pem`)
- Output:
    - `True` if the signature is valid, `False` otherwise

## Changelog

- 0.3.0:
  - Introduce `hmac_sign` tools for HMAC signature generation, support HMAC-SHA1 and HMAC-SHA256 algorithms
  
- 0.2.0:
  - Introduce `aes_encrypt` and `aes_decrypt` tools for AES encryption and decryption of Base64 format ciphertext 

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
