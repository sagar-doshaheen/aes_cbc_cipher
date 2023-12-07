import 'package:aes_cbc_cipher/src/index.dart';

extension CryptoDartHelperExt on CryptoDart {
  Tuple2<Uint8List, Uint8List> deriveKeyAndIV(
    String passphrase,
    Uint8List salt,
  ) {
    var password = createUint8ListFromString(passphrase);
    Uint8List concatenatedHashes = Uint8List(0);
    Uint8List currentHash = Uint8List(0);
    bool enoughBytesForKey = false;
    Uint8List preHash = Uint8List(0);

    while (!enoughBytesForKey) {
      if (currentHash.isNotEmpty) {
        preHash = Uint8List.fromList(
          currentHash + password + salt,
        );
      } else {
        preHash = Uint8List.fromList(
          password + salt,
        );
      }

      currentHash = Uint8List.fromList(
        md5.convert(preHash).bytes,
      );
      concatenatedHashes = Uint8List.fromList(
        concatenatedHashes + currentHash,
      );
      if (concatenatedHashes.length >= 48) enoughBytesForKey = true;
    }

    final Uint8List keyBytes = concatenatedHashes.sublist(
      0,
      32,
    );
    final Uint8List ivBytes = concatenatedHashes.sublist(
      32,
      48,
    );
    return Tuple2(
      keyBytes,
      ivBytes,
    );
  }

  /// Creates a Uint8List from the string
  /// Parameters: -
  /// * [s]: The string to convert to Uint8List
  Uint8List createUint8ListFromString(String s) {
    final Uint8List ret = Uint8List(s.length);
    for (var i = 0; i < s.length; i++) {
      ret[i] = s.codeUnitAt(i);
    }
    return ret;
  }

  /// Generate a random key and IV for AES encryption
  /// Parameters: -
  /// * [seedLength]: The length of the key and IV in bytes
  Uint8List genRandomWithNonZero(int seedLength) {
    final Random random = Random.secure();
    const int randomMax = 245;
    final Uint8List uint8list = Uint8List(
      seedLength,
    );
    for (int i = 0; i < seedLength; i++) {
      uint8list[i] = random.nextInt(randomMax) + 1;
    }
    return uint8list;
  }
}
