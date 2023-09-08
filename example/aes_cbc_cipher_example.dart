import 'package:aes_cbc_cipher/aes_cbc_cipher.dart';

String get _plainText => 'Hello World!';
void main(List<String> _) {
  //* MARK: - Initialization
  AESCBCCipher().init(
    key: '************************', // <----- Replace with your key
    iv: '****************', // <----- Replace with your iv
  );

  //* MARK: - Encryption
  print("Encrypting '$_plainText'...");
  final String encryptedText = AESCBCCipher().encrypt(_plainText);
  print("Encrypted Text: $encryptedText");

  //* MARK: - Decryption
  final String? decryptedText = AESCBCCipher().decrypt(encryptedText);
  print("Decrypting '$encryptedText'...");
  Future.delayed(
    const Duration(seconds: 2),
    () {
      //* MARK: - Result
      print("Decrypted Text: $decryptedText");
    },
  );
}
