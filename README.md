![macOS](https://img.shields.io/badge/os-macOS-green.svg?style=flat)
![iOS](https://img.shields.io/badge/os-iOS-green.svg?style=flat)
![Linux](https://img.shields.io/badge/os-linux-green.svg?style=flat)
![Apache 2](https://img.shields.io/badge/license-Apache2-blue.svg?style=flat)
![](https://img.shields.io/badge/Swift-3.0-orange.svg?style=flat)
![](https://img.shields.io/badge/Swift-4.0-orange.svg?style=flat)
[![Build Status - Master](https://travis-ci.org/IBM-Swift/BlueCryptor.svg?branch=master)](https://travis-ci.org/IBM-Swift/BlueCryptor)

# BlueCryptor
Swift cross-platform crypto library derived from [IDZSwiftCommonCrypto](https://github.com/iosdevzone/IDZSwiftCommonCrypto).

**Note:** On macOS and iOS, _BlueCryptor_ uses the Apple provided *CommonCrypto* library. On Linux, it uses *libcrypto from the OpenSSL project*.

## Prerequisites

### Swift

* Swift Open Source `swift-3.0.1-RELEASE` toolchain (**Minimum REQUIRED for latest release**)
* Swift Open Source `swift-4.0.0-RELEASE` toolchain (**Recommended**)
* Swift toolchain included in *Xcode Version 9.0 (9A325) or higher*.

### macOS

* macOS 10.11.6 (*El Capitan*) or higher
* Xcode Version 8.3.2 (8E2002) or higher using one of the above toolchains (*Recommended*)
* Xcode Version 9.0  (9A325) or higher using the included toolchain.
* CommonCrypto is provided by macOS

### iOS

* iOS 10.0 or higher
* Xcode Version 8.3.2 (8E2002) or higher using one of the above toolchains (*Recommended*)
* Xcode Version 9.0  (9A325) or higher using the included toolchain.
* CommonCrypto is provided by iOS

### Linux

* Ubuntu 16.04 (or 16.10 but only tested on 16.04)
* One of the Swift Open Source toolchain listed above
* OpenSSL is provided by the distribution

## Build

To build **Cryptor** from the command line:

```
% cd <path-to-clone>
% swift build
```

## Testing

To run the supplied unit tests for **Cryptor** from the command line:

```
% cd <path-to-clone>
% swift build
% swift test
```

## Getting started

```swift
import Cryptor
```

## API

### Cryptor

The following code demonstrates encryption and decryption using `AES` single block CBC mode using optional chaining.
```swift
let key = CryptoUtils.byteArray(fromHex: "2b7e151628aed2a6abf7158809cf4f3c")
let iv = CryptoUtils.byteArray(fromHex: "00000000000000000000000000000000")
let plainText = CryptoUtils.byteArray(fromHex: "6bc1bee22e409f96e93d7e117393172a")

var textToCipher = plainText
if plainText.count % Cryptor.Algorithm.aes.blockSize != 0 {
	textToCipher = CryptoUtils.zeroPad(byteArray: plainText, blockSize: Cryptor.Algorithm.aes.blockSize)
}
let cipherText = Cryptor(operation: .encrypt, algorithm: .aes, options: .none, key: key, iv: iv).update(byteArray: textToCipher)?.final()
		
print(CryptoUtils.hexString(from: cipherText!))
		
let decryptedText = Cryptor(operation: .decrypt, algorithm: .aes, options: .none, key: key, iv: iv).update(byteArray: cipherText!)?.final()

print(CryptoUtils.hexString(from: decryptedText!))
```

### Digest

The following example illustrates generating an `MD5` digest from both a `String` and an instance of `NSData`.
``` swift
let qbfBytes : [UInt8] = [0x54,0x68,0x65,0x20,0x71,0x75,0x69,0x63,0x6b,0x20,0x62,0x72,0x6f,0x77,0x6e,0x20,0x66,0x6f,0x78,0x20,0x6a,0x75,0x6d,0x70,0x73,0x20,0x6f,0x76,0x65,0x72,0x20,0x74,0x68,0x65,0x20,0x6c,0x61,0x7a,0x79,0x20,0x64,0x6f,0x67,0x2e]
let qbfString = "The quick brown fox jumps over the lazy dog."

// String...
let md5 = Digest(using: .md5)
md5.update(string: qfbString)
let digest = md5.final()

// NSData using optional chaining...
let qbfData = CryptoUtils.data(from: qbfBytes)
let digest = Digest(using: .md5).update(data: qbfData)?.final()
```

### HMAC

The following demonstrates generating an `SHA256` HMAC using byte arrays for keys and data.
```swift
let myKeyData = "0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b"
let myData = "4869205468657265"
let key = CryptoUtils.byteArray(fromHex: myKeyData)
let data : [UInt8] = CryptoUtils.byteArray(fromHex: myData)

let hmac = HMAC(using: HMAC.Algorithm.sha256, key: key).update(byteArray: data)?.final()
```

### Key Derivation

The following illustrates generating a key using a password, salt, number of rounds and a specified derived key length using the SHA1 algorithm. Then it shows how to generate a `String` from resultant key.
```swift
let password = "password"
let salt = salt
let rounds: UInt = 2
let derivedKeyLen = 20

let key = PBKDF.deriveKey(fromPassword: password, salt: salt, prf: .sha1, rounds: rounds, derivedKeyLength: derivedKeyLen)
let keyString = CryptoUtils.hexString(from: key)
```

### Random Byte Generation

The following demonstrates generating random bytes of a given length.
```swift
let numberOfBytes = 256*256
do {
	let randomBytes = try Random.generate(byteCount: numberOfBytes)
} catch {
  	print("Error generating random bytes")
}
```

### Utilities

**Cryptor** also provides a set of data manipulation utility functions for conversion of data from various formats:
- To byteArray (`[UInt8]`)
	- From hex string
	- From UTF8 string
- To `Data`
	- From hex string
	- From byte array (`[UInt8]`)
- To `NSData`
	- From hex string
	- From byte array (`[UInt8]`)
- To `NSString`
	- From byte array (`[UInt8]`)
- To hexList (`String`)
	- From byte array (`[UInt8]`)

Also provided are an API to pad a byte array (`[UInt8]`) such that it is an integral number of `block size in bytes` long.
- ```func zeroPad(byteArray: [UInt8], blockSize: Int) -> [UInt8]```
- ```func zeroPad(string: String, blockSize: Int) -> [UInt8]```

## Restrictions

The following algorithm is not available on Linux since it is not supported by *OpenSSL*.
- Digest: MD2

In all cases, use of unsupported APIs or algorithms will result in a Swift `fatalError()`, terminating the program and should be treated as a programming error.
