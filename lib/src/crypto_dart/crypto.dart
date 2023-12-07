class CryptoDart {
  /// Singleton instance
  static final CryptoDart _instance = CryptoDart._internal();
  factory CryptoDart() => _instance;
  CryptoDart._internal();

  //* MARK: - Private Variables
  //? =========================================================
  late final String passPhrase;
  late final int seedLength;

  //* MARK: - Public Methods
  //? =========================================================

  /// Initializes the [CryptoDart] instance with the given [phrase] and [seedSize].
  /// Parameters: -
  /// * [phrase] - The phrase to use for encryption and decryption.
  /// * [seedSize] - The size of the seed to use for encryption and decryption. Default is __8__.
  bool init({
    required String phrase,
    int seedSize = 8,
  }) {
    try {
      passPhrase = phrase;
      seedLength = seedSize;
      return true;
    } catch (e) {
      return false;
    }
  }
}
