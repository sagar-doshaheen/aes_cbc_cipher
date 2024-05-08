import 'dart:io';

import 'package:aes_cbc_cipher/src/index.dart';
import 'package:encrypt/encrypt.dart' as enc;

/// AES Helper
/// Description: -
/// * A singleton class that provides AES encryption and decryption
/// * Uses the [encrypt](https://pub.dev/packages/encrypt) package
/// <br>
/// Functions: -
/// * [encrypt] - Encrypts the given [plainText] and returns the encrypted [String] in Base64 format
/// * [decrypt] - Decrypts the given [encryptedText] and returns the decrypted [String]
class AESCBCCipher {
  /// Singleton instance
  static final AESCBCCipher _instance = AESCBCCipher._internal();

  factory AESCBCCipher() {
    return _instance;
  }

  AESCBCCipher._internal();

  //* MARK: - Private Variables
  //? =========================================================

  /// In AES (Advanced Encryption Standard) encryption,
  /// a "key" is a secret, cryptographic parameter that
  /// determines how the data is transformed during
  /// encryption and decryption. It's a series of bits
  /// used by the algorithm to perform the encryption
  /// and must be kept confidential. AES supports different
  /// key sizes, such as 128, 192, or 256 bits, with
  /// longer keys generally providing stronger security.
  /// The choice of key size affects the complexity of
  /// the encryption process and the level of protection
  /// against unauthorized access. A secure and well-protected
  /// key is essential for the effectiveness of AES encryption.
  /// ! IMPORTANT: The key must be 32 characters long
  late final enc.Key? _key;

  /// In AES (Advanced Encryption Standard) encryption,
  /// an "IV" stands for Initialization Vector.
  /// It is a random or unique value added to the
  /// encryption process to ensure that even when
  /// encrypting the same data with the same key,
  /// the resulting ciphertext varies, enhancing security.
  /// The IV prevents patterns in the plaintext
  /// from showing up in the ciphertext, making
  /// AES encryption more resistant to certain attacks.
  /// The IV is typically public and may be sent alongside
  /// the ciphertext, but it should be different for
  /// each encryption session or data block to maintain security.
  /// ! IMPORTANT: The IV must be 16 characters long
  late final enc.IV? _iv;

  /// Advanced Encryption Standard
  late final enc.AES? _aes;

  /// Encrypter
  late final enc.Encrypter? _encrypter;

  //* MARK: - Public Functions
  //? =========================================================

  /// Initializes the AESCBCCipher with a 32 byte [key] and a 16 byte [iv]
  /// Parameters: -
  /// * [key] - The 32 byte key to be used for encryption and decryption
  /// * [iv] - The 16 byte initialization vector to be used for encryption and decryption
  /// * [padding] - The padding type to be used for encryption and decryption. Default is [AESPaddingType.pkcs7]
  void init({
    required String key,
    required String iv,
    AESPaddingType padding = AESPaddingType.pkcs7,
  }) {
    _key = enc.Key.fromUtf8(key);
    _iv = enc.IV.fromUtf8(iv);
    _aes = enc.AES(
      _key!,
      mode: enc.AESMode.cbc,
      padding: padding.value,
    );
    _encrypter = enc.Encrypter(_aes!);

    final Object? testResult = _test();
    if (testResult != null) {
      return;
    }
    print(
      'AESCBCCipher initialized successfully!',
      // name: 'AESCBCCipher',
      // time: DateTime.now(),
    );
  }

  /// Encrypts the given [plainText] and returns the encrypted [String] in Base64 format
  /// Parameters: -
  /// * [plainText] - The [String] to be encrypted
  String encrypt(
    String plainText, {
    bool isTest = false,
  }) {
    assert(
      _encrypter != null,
      'init method not called yet. Please initialize the AESCBCCipher first.',
    );
    final enc.Encrypted encrypted = _encrypter!.encrypt(
      plainText,
      iv: _iv,
    );
    return encrypted.base64;
  }

  /// Decrypts the given [encryptedText] and returns the decrypted [String]
  /// Parameters: -
  /// * [encryptedText] - The [String] to be decrypted
  /// Throws: -
  /// * [FormatException] - If the given [encryptedText] is not in Base64 format
  /// * [ArgumentError] - If the given [encryptedText] is not in the correct format
  /// * [StateError] - If the given [encryptedText] is not in the correct format
  /// * [PaddingException] - If the given [encryptedText] is not in the correct format
  /// * [InvalidPaddingException] - If the given [encryptedText] is not in the correct format
  /// * [InvalidArgumentError] - If the given [encryptedText] is not in the correct format
  /// * [InvalidKeyException] - If the given [encryptedText] is not in the correct format
  /// * [InvalidAlgorithmError] - If the given [encryptedText] is not in the correct format
  /// * [InvalidIVException] - If the given [encryptedText] is not in the correct format
  /// * [InvalidBlockException] - If the given [encryptedText] is not in the correct format
  String? decrypt(
    String encryptedText, {
    bool isTest = false,
  }) {
    assert(
      _encrypter != null,
      'init method not called yet. Please initialize the AESCBCCipher first.',
    );
    String? strToReturn = '';
    try {
      final enc.Encrypted encrypted = enc.Encrypted.fromBase64(
        encryptedText,
      );
      final String decrypted = _encrypter!.decrypt(
        encrypted,
        iv: _iv,
      );
      strToReturn = decrypted;
    } on FormatException {
      strToReturn =
          'FormatException: The given encryptedText is not in Base64 format';
    } on ArgumentError {
      strToReturn =
          'ArgumentError: The given encryptedText is not in the correct format';
    } on StateError {
      strToReturn =
          'StateError: The given encryptedText is not in the correct format';
    } catch (e) {
      strToReturn = 'An unexpected error occurred during decryption: $e';
    }
    return strToReturn;
  }

  /// Encrypts a file located at the given [filePath] using AES-CBC cipher.
  /// Returns the path of the encrypted file.
  ///
  /// Throws an assertion error if the [enc.Encrypter] is not initialized.
  /// The [enc.Encrypter] must be initialized by calling the [init] method of the AESCBCCipher class.
  ///
  /// The file is read as bytes and encrypted using the [enc.Encrypter] with the [enc.IV] as the initialization vector.
  /// The encrypted bytes are then written to a new file with the same name as the original file, but with the extension ".aes".
  /// The encrypted file is saved in the application documents directory.
  Future<String?> encryptFile({
    required String filePath,
  }) async {
    assert(
      _encrypter != null,
      'init method not called yet. Please initialize the AESCBCCipher first.',
    );
    final File file = File(filePath);
    final List<int> bytesToEncrypt = await file.readAsBytes();

    final enc.Encrypted encrypted = _encrypter!.encryptBytes(
      bytesToEncrypt,
      iv: _iv,
    );

    final String fileName = filePath.split('/').last.split('.').first;

    final String dir = filePath
        .split('/')
        .sublist(0, filePath.split('/').length - 1)
        .join('/');

    final File encryptedFile = File('$dir/$fileName.aes');
    await encryptedFile.writeAsBytes(encrypted.bytes);

    return encryptedFile.path;
  }

  /// Decrypts a file using AES CBC cipher.
  ///
  /// This method takes in the path of an encrypted file and decrypts it using the AES CBC cipher algorithm.
  /// The decrypted file is saved in the same directory as the encrypted file with the correct file extension.
  ///
  /// Parameters:
  /// - `encryptedFilePath`: The path of the encrypted file to be decrypted.
  ///
  /// Returns:
  /// A [Future] that completes with the path of the decrypted file.
  ///
  /// Throws:
  /// - An assertion error if the `init` method has not been called to initialize the AES CBC cipher.
  Future<String?> decryptFile({
    required String encryptedFilePath,
  }) async {
    assert(
      _encrypter != null,
      'init method not called yet. Please initialize the AESCBCCipher first.',
    );

    final File encryptedFile = File(encryptedFilePath);
    final List<int> encryptedBytes = await encryptedFile.readAsBytes();

    final enc.Encrypted encrypted = enc.Encrypted(
      Uint8List.fromList(encryptedBytes),
    );

    final List<int> decryptedBytes = _encrypter!.decryptBytes(
      encrypted,
      iv: _iv,
    );

    final String base64Decoded = base64Encode(
      decryptedBytes,
    );

    // Find the directory where the encrypted file is stored
    final encryptedDirectory = encryptedFile.parent;

    // Infer the file type from the base64 string
    final fileType = _inferFileTypeFromBase64(base64Decoded);

    // Get the file name from the encrypted file path
    final String fileName = encryptedFilePath.split('/').last.split('.').first;

    // Construct the new file path with the correct file extension
    final decryptedFilePath =
        '${encryptedDirectory.path}/$fileName.$fileType';

    // Write the decrypted file to the new path
    final decryptedFile = File(decryptedFilePath);
    await decryptedFile.writeAsBytes(decryptedBytes);

    return decryptedFilePath;
  }

  //* MARK: - Private Functions
  //? =========================================================
  /// Private function to test the initialized values
  Object? _test() {
    try {
      final plainText = 'Hello, World!';
      final encryptedText = encrypt(plainText);
      final decryptedText = decrypt(encryptedText);
      final bool didTestSucceed = decryptedText == plainText;
      if (!didTestSucceed) {
        print(
          'AESCBCCipher initialization failed. Please check the key and iv values.',
        );
        return Exception(
          'AESCBCCipher initialization failed. Please check the key and iv values.',
        );
      }
      return null;
    } catch (e) {
      print(
        'AESCBCCipher initialization failed. Please check the key and iv values.',
      );
      return e;
    }
  }

  // Function to infer file type from base64 string
  String _inferFileTypeFromBase64(String base64String) {
    final String firstChar = base64String.substring(0, 1);
    switch (firstChar) {
      case 'i':
        return 'png';
      case 'R':
        return 'gif';
      case '/':
        return 'jpg';
      case 'J':
        return 'pdf';
      default:
        return 'png';
    }
  }
}
