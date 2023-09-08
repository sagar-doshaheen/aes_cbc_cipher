enum AESPaddingType {
  pkcs7,
  iso7816,
  ansix923,
  zeroPadding,
}

extension AESPaddingTypeExt on AESPaddingType {
  String get value {
    switch (this) {
      case AESPaddingType.pkcs7:
        return 'PKCS7';
      case AESPaddingType.iso7816:
        return 'ISO7816';
      case AESPaddingType.ansix923:
        return 'ANSIX923';
      case AESPaddingType.zeroPadding:
        return 'ZEROPADDING';
      default:
        return 'pkcs7';
    }
  }
}
