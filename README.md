# BlueCryptor
Swift cross-platform crypto library derived from [IDZSwiftCommonCrypto](https://github.com/iosdevzone/IDZSwiftCommonCrypto).

## Status
The current version has been updated for Swift 3.0 and includes new packaging. The API presented by this framework is *NOT* the same as the one presented by the original. It has been updated to conform to the Swift 3.0 API Guidelines.

This package is functionally complete and has all current relevant tests passing on both OS X and Linux. 

**Note:** On OS X, BlueCryptor uses the Apple provided *CommonCrypto* library. On Linux, it uses *libcrypto from OpenSSL*.

## Prerequisites

### Swift
* Swift Open Source `swift-DEVELOPMENT-SNAPSHOT-2016-05-03-a` toolchain (**Minimum REQUIRED for latest release**)
* Swift Open Source `swift-DEVELOPMENT-SNAPSHOT-2016-05-09-a` toolchain (*Recommended*)

### OS X

* OS X 10.11.0 (*El Capitan*) or higher
* Xcode Version 7.3.1 (7D1012) or higher using the one of the above toolchains (*Recommended*)

### Linux

* Ubuntu 15.10 (or 14.04 but only tested on 15.10)
* One of the Swift Open Source toolchains listed above

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

let cipherText = Cryptor(operation: .encrypt, algorithm: .aes, options: .none, key: key, iv: iv).update(byteArray: plainText)?.final()
		
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
ley keyString = CryptoUtils.hexString(from: key)
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

Due to an issue with API differences between the `Foundation` implementation on **OS X** versus the implementation on **Linux**, the following API usuage is not available on **Linux**.  It remains available on **OS X**.  Once the issue is resolved, this API usage will be available on *both* platforms. This API is an extension to `NSData` that allows generation of a `digest` from a previously populated `NSData` instance.

```swift
let shaShortBlock = "abc"
let sha224BlockOutput = "23097d223405d8228642a477bda255b32aadbce4bda0b3f7e36c9da7"
let sha256BlockOutput = "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
let sha384BlockOutput = "cb00753f45a35e8bb5a03d699ac65007272c32ab0eded1631a8b605a43ff5bed8086072ba1e7cc2358baeca134c825a7"
let sha512BlockOutput = "ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f"
let theData: NSData = shaShortBlock.data(using:NSUTF8StringEncoding)!
XCTAssertEqual(theData.sha224, CryptoUtils.data(fromHex: sha224BlockOutput))
XCTAssertEqual(theData.sha256, CryptoUtils.data(fromHex: sha256BlockOutput))
XCTAssertEqual(theData.sha384, CryptoUtils.data(fromHex: sha384BlockOutput))
XCTAssertEqual(theData.sha512, CryptoUtils.data(fromHex: sha512BlockOutput))
```
These tests pass on **OSX** but will fail with the following error on **Linux**: `This API not supported on Linux.`

The following algorithms are not available on Linux since they are not supported by *OpenSSL*.
- Digest: MD2, SHA1
- HMAC: SHA1

In all cases, use of unsupported APIs or algorithms will result in a Swift `fatalError()`, terminating the program and should be treated as a programming error.
