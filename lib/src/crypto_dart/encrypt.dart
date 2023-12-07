import 'package:aes_cbc_cipher/src/index.dart';
import 'package:encrypt/encrypt.dart' as enc;

extension CryptoDartEncryptionExt on CryptoDart {
  /// Encrypts the given [plainText] using the [passPhrase] and returns the
  /// encrypted text as a [String].
  /// Parameters: -
  /// * [plainText] - The text to encrypt.
  String? encrypt(String? plainText) {
    try {
      if (plainText == null || plainText.isEmpty) {
        return null;
      }

      final Uint8List salt = genRandomWithNonZero(8);
      final Tuple2<Uint8List, Uint8List> keyAndIV = deriveKeyAndIV(
        passPhrase,
        salt,
      );
      final enc.Key key = enc.Key(
        keyAndIV.item1,
      );
      final enc.IV iv = enc.IV(
        keyAndIV.item2,
      );

      final enc.Encrypter encrypter = enc.Encrypter(
        enc.AES(
          key,
          mode: enc.AESMode.cbc,
          padding: "PKCS7",
        ),
      );
      final encrypted = encrypter.encrypt(
        plainText,
        iv: iv,
      );
      final Uint8List encryptedBytesWithSalt = Uint8List.fromList(
        createUint8ListFromString(
              "Salted__",
            ) +
            salt +
            encrypted.bytes,
      );
      return base64.encode(
        encryptedBytesWithSalt,
      );
    } catch (error) {
      rethrow;
    }
  }
}
