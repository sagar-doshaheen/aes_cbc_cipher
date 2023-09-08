import 'package:test/test.dart';
import 'package:aes_cbc_cipher/aes_cbc_cipher.dart';

void main() {
  test('Encryption Test', () {
    AESCBCCipher().init(
      key: 'rKK6mMiKS7XyJ4jWKwXLmqcGnNXAj8xX', // <----- Replace with your key
      iv: 'Il296XQ9jW5o3Qb9', // <----- Replace with your iv
    );

    final String text = 'Hello World!';

    print("Encrypting '$text'...");
    final String encryptedText = AESCBCCipher().encrypt(text);
    print("Encrypted Text: $encryptedText");
    final String? decryptedText = AESCBCCipher().decrypt(encryptedText);
    print("Decrypting '$encryptedText'...");
    expect(decryptedText, text);
  });
}
