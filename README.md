[![APIDoc](https://img.shields.io/badge/docs-kitura.io-1FBCE4.svg)](https://www.kitura.io/packages.html#all)
[![SwiftPackageIndex](https://img.shields.io/endpoint?url=https%3A%2F%2Fswiftpackageindex.com%2Fapi%2Fpackages%2FKitura%2FBlueCryptor%2Fbadge%3Ftype%3Dswift-versions)](https://swiftpackageindex.com/Kitura/BlueCryptor)
[![TravisCI](https://travis-ci.org/Kitura/BlueCryptor.svg?branch=master)](https://travis-ci.org/Kitura/BlueCryptor)
[![](https://img.shields.io/endpoint?url=https%3A%2F%2Fswiftpackageindex.com%2Fapi%2Fpackages%2FKitura%2FBlueCryptor%2Fbadge%3Ftype%3Dplatforms)](https://swiftpackageindex.com/Kitura/BlueCryptor)
[![License](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](https://opensource.org/licenses/Apache-2.0)

# BlueCryptor
Swift cross-platform crypto library derived from [IDZSwiftCommonCrypto](https://github.com/iosdevzone/IDZSwiftCommonCrypto).

**IMPORTANT NOTE:** This release is **NOT** entirely source code compatible with previous releases.  There are instances where *exceptions* are thrown now instead of the framework calling *fatalError()*.  This means that there are more *recoverable* errors in the library than before.  The only time that *fatalError()* is called is to indicate either a *programming error* or a *non-recoverable system error*.

**Note:** On macOS and iOS, _BlueCryptor_ uses the Apple provided *CommonCrypto* library. On Linux, it uses *libcrypto from the OpenSSL project*.

## Prerequisites

### Swift

* Swift Open Source `swift-5.1-RELEASE` toolchain (**Minimum REQUIRED for latest release**)
* Swift Open Source `swift-5.4-RELEASE` toolchain (**Recommended**)
* Swift toolchain included in *Xcode Version 11.0 or higher*.

### macOS

* macOS 11.5 (*Big Sur*) or higher.
* Xcode Version 11.0 or higher using one of the above toolchains.
* Xcode Version 13.4 or higher using the included toolchain (*Recommended*).
* CommonCrypto is provided by macOS.

### iOS

* iOS 14.5 or higher
* Xcode Version 11.0 or higher using one of the above toolchains.
* Xcode Version 13.4 or higher using the included toolchain (*Recommended*).
* CommonCrypto is provided by iOS.

### Linux

* Ubuntu 16.04 (or 16.10 but only tested on 16.04) and 18.04.
* One of the Swift Open Source toolchain listed above.
* OpenSSL is provided by the distribution.  **Note:** 1.0.x, 1.1.x and later releases of OpenSSL are supported.
* The appropriate **libssl-dev** package is required to be installed when building.

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

### Including in your project

#### Swift Package Manager

To include BlueCryptor into a Swift Package Manager package, add it to the `dependencies` attribute defined in your `Package.swift` file. You can select the version using the `majorVersion` and `minor` parameters. For example:
```
	dependencies: [
		.Package(url: "https://github.com/Kitura/BlueCryptor.git", majorVersion: <majorVersion>, minor: <minor>)
	]
```

#### Carthage
To include BlueCryptor in a project using Carthage, add a line to your `Cartfile` with the GitHub organization and project names and version. For example:
```
	github "Kitura/BlueCryptor" ~> <majorVersion>.<minor>
```

#### CocoaPods
To include BlueCryptor in a project using CocoaPods, you just add `BlueCryptor` to your `Podfile`, for example:
```
    platform :ios, '14.5'

    target 'MyApp' do
        use_frameworks!
        pod 'BlueCryptor'
    end
```

### Before starting

The first thing you need to do is import the Cryptor framework.  This is done by the following:
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
do {
	let cipherText = try Cryptor(operation: .encrypt, algorithm: .aes, options: .none, key: key, iv: iv).update(byteArray: textToCipher)?.final()
		
	print(CryptoUtils.hexString(from: cipherText!))
		
	let decryptedText = try Cryptor(operation: .decrypt, algorithm: .aes, options: .none, key: key, iv: iv).update(byteArray: cipherText!)?.final()

	print(CryptoUtils.hexString(from: decryptedText!))
} catch let error {
	guard let err = error as? CryptorError else {
		// Handle non-Cryptor error...
		return
	}
	// Handle Cryptor error... (See Status.swift for types of errors thrown)
}
```

### Digest

The following example illustrates generating an `SHA1` digest from both a `String` and an instance of `NSData`.
```swift
let qbfBytes : [UInt8] = [0x54,0x68,0x65,0x20,0x71,0x75,0x69,0x63,0x6b,0x20,0x62,0x72,0x6f,0x77,0x6e,0x20,0x66,0x6f,0x78,0x20,0x6a,0x75,0x6d,0x70,0x73,0x20,0x6f,0x76,0x65,0x72,0x20,0x74,0x68,0x65,0x20,0x6c,0x61,0x7a,0x79,0x20,0x64,0x6f,0x67,0x2e]
let qbfString = "The quick brown fox jumps over the lazy dog."

// String...
let sha1 = Digest(using: .sha1)
sha1.update(string: qfbString)
let digest = sha1.final()

// NSData using optional chaining...
let qbfData = CryptoUtils.data(from: qbfBytes)
let digest = Digest(using: .sha1).update(data: qbfData)?.final()
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
do {
	let key = PBKDF.deriveKey(fromPassword: password, salt: salt, prf: .sha1, rounds: rounds, derivedKeyLength: derivedKeyLen)
	let keyString = CryptoUtils.hexString(from: key)
} catch let error {
	guard let err = error as? CryptorError else {
		// Handle non-Cryptor error...
		return
	}
	// Handle Cryptor error... (See Status.swift for types of errors thrown)
}
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

In all cases, use of unsupported APIs or algorithms will result in a Swift `fatalError()`, terminating the program and should be treated as a programming error.

## Community

We love to talk server-side Swift and Kitura. Join our [Slack](http://swift-at-ibm-slack.mybluemix.net/) to meet the team!

## License

This library is licensed under Apache 2.0. Full license text is available in [LICENSE](https://github.com/Kitura/BlueCryptor/blob/master/LICENSE).
