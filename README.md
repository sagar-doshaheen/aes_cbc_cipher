# AESCBCCipher

The `AESCBCCipher` is a singleton class that provides AES encryption and decryption functionality using the `encrypt` package. It is used to encrypt and decrypt data using the AES (Advanced Encryption Standard) algorithm in CBC (Cipher Block Chaining) mode.

## Functions

### `init`

Initializes the `AESCBCCipher` with a 32-byte key and a 16-byte initialization vector (IV). It takes the following parameters:
- `key` (required): The 32-byte key to be used for encryption and decryption.
- `iv` (required): The 16-byte initialization vector to be used for encryption and decryption.
- `padding` (optional): The padding type to be used for encryption and decryption. The default is `AESPaddingType.pkcs7`.

### `encrypt`

Encrypts the given plaintext and returns the encrypted string in Base64 format. It takes the following parameters:
- `plainText`: The string to be encrypted.
- `isTest` (optional): A boolean flag indicating whether the encryption is for testing purposes. Default is `false`.

### `decrypt`

Decrypts the given encrypted text and returns the decrypted string. It takes the following parameters:
- `encryptedText`: The string to be decrypted.
- `isTest` (optional): A boolean flag indicating whether the decryption is for testing purposes. Default is `false`.

The `decrypt` function may throw the following exceptions:
- `FormatException`: If the given `encryptedText` is not in Base64 format.
- `ArgumentException`: If the given `encryptedText` is not in the correct format.
- `StateError`: If the given `encryptedText` is not in the correct format.

Please note that the `init` function must be called before using the `encrypt` and `decrypt` functions. If the `init` function is not called, an assertion error will be thrown.

The `AESCBCCipher` class also has private functions that are used internally for testing and initialization purposes.
