# BlueCryptor
Crypto library based on CommonCrypto and derived from [IDZSwiftCommonCrypto](https://github.com/iosdevzone/IDZSwiftCommonCrypto)

## Status
The current version has been updated for Swift 3.0 and includes new packaging. The current version is only usuable on OS X (or where the CommonCrypto library is installed). The API presented by this framework is *NOT* the same as the one presented by the original. It has been updated to conform to the Swift 3.0 API Guidelines.

## Next Steps
When running on Linux, replace the calls to the CommonCrypto APIs with calls to the libcrypto API that is part of OpenSSL.
