import 'package:test/test.dart';
import 'package:aes_cbc_cipher/aes_cbc_cipher.dart';

void main() {
  test('Encryption Test', () {
    AESCBCCipher().init(
      key: '0C22364E5F5A222024180A28262A0623', // <----- Replace with your key
      iv: '4c58db71c1b13c3b', // <----- Replace with your iv
    );

    final String text = 'BTXPG2457A';

    print("Encrypting '$text'...");
    final String encryptedText = AESCBCCipher().encrypt(text);
    print("Encrypted Text: $encryptedText");
    final String? decryptedText = AESCBCCipher().decrypt(encryptedText);
    print("Decrypting '$encryptedText'...");
    expect(decryptedText, text);
  });

  test(
    'Crypto Dart Test',
    () {
      CryptoDart().init(
        phrase: "some-random-phrase",
      );
      String plainText = '''
Lorem Ipsum is simply dummy text of the printing and typesetting industry.
Lorem Ipsum has been the industry's standard dummy text ever since the 1500s,
when an unknown printer took a galley of type and scrambled it to make a type
specimen book. It has survived not only five centuries, but also the leap into
electronic typesetting, remaining essentially unchanged. It was popularised
in the 1960s with the release of Letraset sheets containing Lorem Ipsum passages,
and more recently with desktop publishing software like Aldus PageMaker including
versions of Lorem Ipsum.
''';
      var encrypted = CryptoDart().encrypt(plainText);
      print("Plain Text: $plainText");
      print("Encrypted: $encrypted");
      expect(encrypted, isNotNull);

      var decrypted = CryptoDart().decrypt(encrypted);
      print("Decrypted: $decrypted");
      expect(decrypted, isNotNull);

      expect(plainText, decrypted);
    },
  );
}
