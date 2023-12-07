import 'package:aes_cbc_cipher/src/index.dart';
import 'package:encrypt/encrypt.dart' as enc;

extension CryptoDartDecryptionExt on CryptoDart {
  /// Decrypts the given [encryptedText] using the [passPhrase] and returns the
  /// decrypted text as a [String].
  /// Parameters: -
  /// * [encryptedText] - The text to decrypt.
  String? decrypt(String? encryptedText) {
    try {
      if (encryptedText == null || encryptedText.isEmpty) {
        return null;
      }
      final Uint8List encryptedBytesWithSalt = base64.decode(
        encryptedText,
      );

      final Uint8List encryptedBytes = encryptedBytesWithSalt.sublist(
        16,
        encryptedBytesWithSalt.length,
      );
      final salt = encryptedBytesWithSalt.sublist(8, 16);
      final Tuple2<Uint8List, Uint8List> keyAndIV =
          deriveKeyAndIV(passPhrase, salt);
      final enc.Key key = enc.Key(
        keyAndIV.item1,
      );
      final enc.IV iv = enc.IV(keyAndIV.item2);

      final enc.Encrypter encrypter = enc.Encrypter(
        enc.AES(
          key,
          mode: enc.AESMode.cbc,
          padding: "PKCS7",
        ),
      );
      final String decrypted = encrypter.decrypt64(
        base64.encode(encryptedBytes),
        iv: iv,
      );
      return decrypted;
    } catch (error) {
      rethrow;
    }
  }
}
