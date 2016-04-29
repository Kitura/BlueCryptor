# BlueCryptor
Crypto library based on CommonCrypto and derived from [IDZSwiftCommonCrypto](https://github.com/iosdevzone/IDZSwiftCommonCrypto).

## Status
The current version has been updated for Swift 3.0 and includes new packaging. The API presented by this framework is *NOT* the same as the one presented by the original. It has been updated to conform to the Swift 3.0 API Guidelines.

This package is functionally complete and has all current tests passing on by OS X and Linux. 

**Note:** On OS X, BlueCrypto uses the Apple provided *CommonCrypto* library. On Linux, it uses *libcrypto from OpenSSL*.

## Prerequisites

### Swift
* Swift Open Source `swift-DEVELOPMENT-SNAPSHOT-2016-04-25-a` toolchain or higher (**REQUIRED for latest release**)

### OS X

* OS X 10.11.0 (*El Capitan*) or higher
* Xcode Version 7.3.1 (7D1012) or higher using the above toolchain (*Recommended*)

### Linux

* Ubuntu 15.10 (or 14.04 but only tested on 15.10)
* Swift Open Source toolchain listed above

## Build

To build **Cryptor** from the command line:

```
% cd <path-to-clone>
% swift build
```

## Get started

```
import Crypto
```

## API

**TBD**
