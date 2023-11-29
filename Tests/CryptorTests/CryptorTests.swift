//
//  CryptorTests.swift
//  CryptorTests
//
// 	Licensed under the Apache License, Version 2.0 (the "License");
// 	you may not use this file except in compliance with the License.
// 	You may obtain a copy of the License at
//
// 	http://www.apache.org/licenses/LICENSE-2.0
//
// 	Unless required by applicable law or agreed to in writing, software
// 	distributed under the License is distributed on an "AS IS" BASIS,
// 	WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// 	See the License for the specific language governing permissions and
// 	limitations under the License.
//

import XCTest
import Foundation
@testable import Cryptor

#if os(macOS) || os(iOS) || os(tvOS) || os(watchOS) || os(visionOS)
	import CommonCrypto
#elseif os(Linux)
	import OpenSSL
#endif

import Dispatch

class CryptorTests: XCTestCase {
	
	static var allTests: [(String, (CryptorTests) -> () throws -> Void)] {
		
		return [
			("test_fatalError_keySize", test_fatalError_keySize),
			("test_fatalError_AES_CBC_ivSize", test_fatalError_AES_CBC_ivSize),
			("test_Cryptor_AES_ECB", test_Cryptor_AES_ECB),
			("test_Cryptor_AES_ECB_Padded", test_Cryptor_AES_ECB_Padded),
			("test_Cryptor_AES_ECB_2", test_Cryptor_AES_ECB_2),
			("test_Cryptor_AES_ECB_Short", test_Cryptor_AES_ECB_Short),
			("test_Cryptor_AES_CBC_1", test_Cryptor_AES_CBC_1),
			("test_Cryptor_DES_EBC_1", test_Cryptor_DES_EBC_1),
			("testMD2", testMD2),
			("testMD5_1", testMD5_1),
			("test_Digest_MD5_NSData", test_Digest_MD5_Data),
			("test_Digest_MD5_NSData", test_Digest_MD5_NSData),
			("test_Digest_MD5_Composition_String", test_Digest_MD5_Composition_String),
			("test_Digest_MD5_Composition_String_2", test_Digest_MD5_Composition_String_2),
			("test_Digest_MD5_Composition_Bytes", test_Digest_MD5_Composition_Bytes),
			("test_Crypto_API", test_Crypto_API),
			("test_Digest_SHA1_String", test_Digest_SHA1_String),
			("test_Digest_SHA224_String", test_Digest_SHA224_String),
			("test_Digest_SHA256_String", test_Digest_SHA256_String),
			("test_Digest_SHA384_String", test_Digest_SHA384_String),
			("test_Digest_SHA512_String", test_Digest_SHA512_String),
			("test_HMAC_MD5", test_HMAC_MD5),
			("test_HMAC_SHA1", test_HMAC_SHA1),
			("test_HMAC_SHA1_NSData", test_HMAC_SHA1_NSData),
			("test_HMAC_SHA1_Data", test_HMAC_SHA1_Data),
			("test_HMAC_SHA224", test_HMAC_SHA224),
			("test_HMAC_SHA256", test_HMAC_SHA256),
			("test_HMAC_SHA384", test_HMAC_SHA384),
			("test_HMAC_SHA512", test_HMAC_SHA512),
			("test_KeyDerivation_deriveKey", test_KeyDerivation_deriveKey),
			("test_KeyDerivation_using_defaultKeySize", test_KeyDerivation_using_defaultKeySize),
			("test_Random_generateBytes", test_Random_generateBytes),
			("test_Random_generateBytesThrow", test_Random_generateBytesThrow),
			("test_Status", test_Status),
			("test_Utilities_arrayFromHexString_lowerCase", test_Utilities_arrayFromHexString_lowerCase),
			("test_Utilities_arrayFromHexString_upperCase", test_Utilities_arrayFromHexString_upperCase),
			("testHexStringFromArray", testHexStringFromArray),
			("testHexNSStringFromArray", testHexNSStringFromArray),
			("testHexListFromArray", testHexListFromArray),
			("testInvalidByteArray", testInvalidByteArray),
			("testZeroPadString", testZeroPadString),
			("testGitHubIssue9", testGitHubIssue9),
			("testGitHubIssue9StringCanary", testGitHubIssue9StringCanary),
			("testGitHubIssue9ArrayCanary", testGitHubIssue9ArrayCanary)
		]
	}
	
	#if os(Linux)
	
		let usingOpenSSL = true

	#else
	
		let usingOpenSSL = false
	
	#endif
	
	
    override func setUp() {
        super.setUp()
        // Put setup code here. This method is called before the invocation of each test method in the class.
    }
	
    override func tearDown() {
        // Put teardown code here. This method is called after the invocation of each test method in the class.
        super.tearDown()
    }
    
	// MARK: - Cryptor tests
	var aesKey1Bytes = CryptoUtils.byteArray(fromHex: "2b7e151628aed2a6abf7158809cf4f3c")
	var aesPlaintext1Bytes = CryptoUtils.byteArray(fromHex: "6bc1bee22e409f96e93d7e117393172a")		// Note: 16 bytes = 1 block AES
	var aesPlaintext2Bytes = CryptoUtils.byteArray(fromHex: "6bc1bee22e409f96e93d7e117393172a3b")	// Note: 17 bytes = 2 blocks AES when padded
	var aesCipherText1Bytes = CryptoUtils.byteArray(fromHex: "3ad77bb40d7a3660a89ecaf32466ef97")
	var aesCipherText2Bytes = CryptoUtils.byteArray(fromHex: "3ad77bb40d7a3660a89ecaf32466ef97a4b2933fde9dabeda5e862373bbccf8c")
	
	/// Test fatal error with invalid key size...
	func test_fatalError_keySize() {
		let tooLongKey = CryptoUtils.byteArray(fromHex: "2b7e151628aed2a6abf7158809cf4f3c2b7e151628aed2a6abf7158809cf4f3c2b7e151628aed2a6abf7158809cf4f3c")
		do {
			_ = try Cryptor(operation:.encrypt,
					   	    algorithm:.aes, options:.ecbMode,
						    key:tooLongKey, iv:Array<UInt8>())
		} catch let error as CryptorError {
			switch error {
			case .invalidKeySize:
				return
			default:
				XCTFail("Did not receive expected exception.")
			}
		} catch {
			XCTFail("Did not received expecte exception.")
		}
		XCTFail("Did not receive exception.")
	}
	
	/// Test fatal error with invalid ivSize...
	func test_fatalError_AES_CBC_ivSize() {
		let key =   CryptoUtils.byteArray(fromHex: "2b7e151628aed2a6abf7158809cf4f3c")
		let iv =    CryptoUtils.byteArray(fromHex: "0000000000000000000000000000000000")
		let plainText = CryptoUtils.byteArray(fromHex: "6bc1bee22e409f96e93d7e117393172a")
		do {
			let _ = try Cryptor(operation:.encrypt, algorithm:.aes, options:.none, key:key, iv:iv).update(byteArray: plainText)?.final()
		} catch let error as CryptorError {
			switch error {
			case .invalidIVSizeOrLength:
				return
			default:
				XCTFail("Did not received expected exception.")
			}
		} catch {
			XCTFail("Did not receive expected exception.")
		}
		XCTFail("Did not receive exception.")
	}

	/// Tests AES ECB without need for padding...
	func test_Cryptor_AES_ECB() {
		do {
			let aesEncrypt = try Cryptor(operation:.encrypt, algorithm:.aes, options:.ecbMode,
			                             key:aesKey1Bytes, iv:Array<UInt8>())
			var dataOut = Array<UInt8>(repeating:UInt8(0), count:aesCipherText1Bytes.count)
			let (c, status) = aesEncrypt.update(byteArrayIn: aesPlaintext1Bytes, byteArrayOut: &dataOut)
			XCTAssert(status == .success)
			XCTAssert(aesCipherText1Bytes.count == Int(c), "Counts are as expected")
			XCTAssertEqual(dataOut, aesCipherText1Bytes, "Obtained expected cipher text")
		} catch let error {
			guard let err = error as? CryptorError else {
				XCTFail("Unexpected exception caught...")
				return
			}
			XCTFail("CryptorError reported unexpectedly, description: \(err.description)")
		}
	}
	
	/// Tests AES ECB requiring padding of text to encrypt...
	func test_Cryptor_AES_ECB_Padded() {
		do {
			let aesEncrypt = try Cryptor(operation:.encrypt, algorithm:.aes, options:.ecbMode,
		                         		 key:aesKey1Bytes, iv:Array<UInt8>())
			var plainText: [UInt8] = aesPlaintext2Bytes
			if aesPlaintext2Bytes.count % Cryptor.Algorithm.aes.blockSize != 0 {
				plainText = CryptoUtils.zeroPad(byteArray: aesPlaintext2Bytes, blockSize: Cryptor.Algorithm.aes.blockSize)
			}
			var dataOut = Array<UInt8>(repeating:UInt8(0), count:plainText.count)
			let (c, status) = aesEncrypt.update(byteArrayIn: plainText, byteArrayOut: &dataOut)
			XCTAssert(status == .success)
			XCTAssert(aesCipherText2Bytes.count == Int(c), "Counts are as expected")
			XCTAssertEqual(dataOut, aesCipherText2Bytes, "Obtained expected cipher text")
		} catch let error {
			guard let err = error as? CryptorError else {
				XCTFail("Unexpected exception caught...")
				return
			}
			XCTFail("CryptorError reported unexpectedly, description: \(err.description)")
		}
	}
	
	/// Tests two blocks of ECB mode AES. Demonstrates weakness in ECB; repeated plaintext block results in repeated ciphertext block.
	func test_Cryptor_AES_ECB_2() {
		let key = aesKey1Bytes
		let plainText = aesPlaintext1Bytes + aesPlaintext1Bytes
		let expectedCipherText = aesCipherText1Bytes + aesCipherText1Bytes
		do {
			let cipherText = try Cryptor(operation:.encrypt, algorithm:.aes, options:.ecbMode, key:key, iv:Array<UInt8>()).update(byteArray: plainText)?.final()
		
			XCTAssert(expectedCipherText.count == cipherText!.count, "Counts are as expected")
			XCTAssert(expectedCipherText == cipherText!, "Obtained expected cipher text")
		} catch let error {
			guard let err = error as? CryptorError else {
				XCTFail("Unexpected exception caught...")
				return
			}
			XCTFail("CryptorError reported unexpectedly, description: \(err.description)")
		}
	}
	
	/// Demonstrates alignment error when plaintext is not an integral number of blocks long.
	func test_Cryptor_AES_ECB_Short() {
		let key = CryptoUtils.byteArray(fromHex: "2b7e151628aed2a6abf7158809cf4f3c")
		let plainText = CryptoUtils.byteArray(fromHex: "6bc1bee22e409f96e93d7e11739317")
		do {
			let cryptor = try Cryptor(operation:.encrypt, algorithm:.aes, options:.ecbMode, key:key, iv:Array<UInt8>())
			let cipherText = cryptor.update(byteArray: plainText)?.final()
			XCTAssert(cipherText == nil, "Expected nil cipherText")
			#if os(macOS) || os(iOS) || os(tvOS) || os(watchOS) || os(visionOS)
				XCTAssertEqual(cryptor.status, Status.alignmentError, "Expected AlignmentError")
			#endif
		} catch let error {
			guard let err = error as? CryptorError else {
				XCTFail("Unexpected exception caught...")
				return
			}
			XCTFail("CryptorError reported unexpectedly, description: \(err.description)")
		}
	}
	
	/// Single block CBC mode. Results should be identical to ECB mode.
	func test_Cryptor_AES_CBC_1() {
		let key =   CryptoUtils.byteArray(fromHex: "2b7e151628aed2a6abf7158809cf4f3c")
		let iv =    CryptoUtils.byteArray(fromHex: "00000000000000000000000000000000")
		let plainText = CryptoUtils.byteArray(fromHex: "6bc1bee22e409f96e93d7e117393172a")
		let expectedCipherText = CryptoUtils.byteArray(fromHex: "3ad77bb40d7a3660a89ecaf32466ef97")

		do {
			let cipherText = try Cryptor(operation:.encrypt, algorithm:.aes, options:.none, key:key, iv:iv).update(byteArray: plainText)?.final()
		
			XCTAssert(expectedCipherText.count == cipherText!.count, "Counts are as expected")
			XCTAssert(expectedCipherText == cipherText!, "Obtained expected cipher text")
		
			print(CryptoUtils.hexString(from: cipherText!))
		
			let decryptedText = try Cryptor(operation:.decrypt, algorithm:.aes, options:.none, key:key, iv:iv).update(byteArray: cipherText!)?.final()
			XCTAssertEqual(decryptedText!, plainText, "Recovered plaintext.")
		} catch let error {
			guard let err = error as? CryptorError else {
				XCTFail("Unexpected exception caught...")
				return
			}
			XCTFail("CryptorError reported unexpectedly, description: \(err.description)")
		}
	}
	
	/// DES EBC mode test 1
	func test_Cryptor_DES_EBC_1() {
		/// Data from table A.1 http://csrc.nist.gov/publications/nistpubs/800-20/800-20.pdf
		let ivs = [
		          	"8000000000000000",
		          	"4000000000000000",
		          	"2000000000000000",
		          	"1000000000000000",
		          	"0800000000000000",
		          	"0400000000000000",
		          	"0200000000000000",
		          	"0100000000000000",
		          	
		          	"0080000000000000",
		          	"0040000000000000",
		          	"0020000000000000",
		          	"0010000000000000",
		          	"0008000000000000",
		          	"0004000000000000",
		          	"0002000000000000",
		          	"0001000000000000",
		          	
		          	"0000800000000000",
		          	"0000400000000000",
		          	"0000200000000000",
		          	"0000100000000000",
		          	"0000080000000000",
		          	"0000040000000000",
		          	"0000020000000000",
		          	"0000010000000000",
		          	
		          	"0000008000000000",
		          	"0000004000000000",
		          	"0000002000000000",
		          	"0000001000000000",
		          	"0000000800000000",
		          	"0000000400000000",
		          	"0000000200000000",
		          	"0000000100000000",
		          	
		          	"0000000080000000",
		          	"0000000040000000",
		          	"0000000020000000",
		          	"0000000010000000",
		          	"0000000008000000",
		          	"0000000004000000",
		          	"0000000002000000",
		          	"0000000001000000",
		          	
		          	"0000000000800000",
		          	"0000000000400000",
		          	"0000000000200000",
		          	"0000000000100000",
		          	"0000000000080000",
		          	"0000000000040000",
		          	"0000000000020000",
		          	"0000000000010000",
		          	
		          	"0000000000008000",
		          	"0000000000004000",
		          	"0000000000002000",
		          	"0000000000001000",
		          	"0000000000000800",
		          	"0000000000000400",
		          	"0000000000000200",
		          	"0000000000000100",
		          	
		          	
		          	"0000000000000080",
		          	"0000000000000040",
		          	"0000000000000020",
		          	"0000000000000010",
		          	"0000000000000008",
		          	"0000000000000004",
		          	"0000000000000002",
		          	"0000000000000001",
		          	]
		
		let ects = [
		           	"95f8a5e5dd31d900", // [0]
			"dd7f121ca5015619", // [1]
			"2e8653104f3834ea", // [2]
			"4bd388ff6cd81d4f", // [3]
			"20b9e767b2fb1456", // [4]
			"55579380d77138ef", // [5]
			"6cc5defaaf04512f", // [6]
			"0d9f279ba5d87260", // [7]
			"d9031b0271bd5a0a", // [8]
			"424250b37c3dd951", // [9]
			"b8061b7ecd9a21e5", // [10]
			"f15d0f286b65bd28", // [11]
			"add0cc8d6e5deba1", // [12]
			"e6d5f82752ad63d1", // [13]
			"ecbfe3bd3f591a5e", // [14]
			"f356834379d165cd", // [15]
			"2b9f982f20037fa9", // [16]
			"889de068a16f0be6", // [17]
			"e19e275d846a1298", // [18]
			"329a8ed523d71aec", // [19]
			"e7fce22557d23c97", // [20]
			"12a9f5817ff2d65d", // [21]
			"a484c3ad38dc9c19", // [22]
			"fbe00a8a1ef8ad72", // [23]
			"750d079407521363", // [24]
			"64feed9c724c2faf", // [25]
			"f02b263b328e2b60", // [26]
			"9d64555a9a10b852", // [27]
			"d106ff0bed5255d7", // [28]
			"e1652c6b138c64a5", // [29]
			"e428581186ec8f46", // [30]
			"aeb5f5ede22d1a36", // [31]
			"e943d7568aec0c5c", // [32]
			"df98c8276f54b04b", // [33]
			"b160e4680f6c696f", // [34]
			"fa0752b07d9c4ab8", // [35]
			"ca3a2b036dbc8502", // [36]
			"5e0905517bb59bcf", // [37]
			"814eeb3b91d90726", // [38]
			"4d49db1532919c9f", // [39]
			"25eb5fc3f8cf0621", // [40]
			"ab6a20c0620d1c6f", // [41]
			"79e90dbc98f92cca", // [42]
			"866ecedd8072bb0e", // [43]
			"8b54536f2f3e64a8", // [44]
			"ea51d3975595b86b", // [45]
			"caffc6ac4542de31", // [46]
			"8dd45a2ddf90796c", // [47]
			"1029d55e880ec2d0", // [48]
			"5d86cb23639dbea9", // [49]
			"1d1ca853ae7c0c5f", // [50]
			"ce332329248f3228", // [51]
			"8405d1abe24fb942", // [52]
			"e643d78090ca4207", // [53]
			"48221b9937748a23", // [54]
			"dd7c0bbd61fafd54", // [55]
			"2fbc291a570db5c4", // [56]
			"e07c30d7e4e26e12", // [57]
			"0953e2258e8e90a1", // [58]
			"5b711bc4ceebf2ee", // [59]
			"cc083f1e6d9e85f6", // [60]
			"d2fd8867d50d2dfe", // [61]
			"06e7ea22ce92708f", // [62]
			"166b40b44aba4bd6" // [63]
			
		]
		
		let key = CryptoUtils.byteArray(fromHex: "0101010101010101")
		
		for i in 0 ..< ivs.count {
			let iv = CryptoUtils.byteArray(fromHex: ivs[i])
			do {
				let cipherText = try Cryptor(operation:.encrypt, algorithm:.des, options:.ecbMode, key:key, iv:Array<UInt8>()).update(byteArray: CryptoUtils.byteArray(fromHex: ivs[i]))?.final()
				print("\"\(CryptoUtils.hexString(from: cipherText!))\", // [\(i)]")
				XCTAssertEqual(CryptoUtils.byteArray(fromHex: ects[i]), cipherText!, "Obtained expected cipher text")
				let decryptor = try Cryptor(operation:.decrypt, algorithm:.des, options:.ecbMode, key:key, iv:iv)
				let decryptedText = decryptor.update(byteArray: cipherText!)?.final()
				XCTAssertEqual(decryptedText!, iv, "Recovered plaintext.")
			} catch let error {
				guard let err = error as? CryptorError else {
					XCTFail("Unexpected exception caught...")
					return
				}
				XCTFail("CryptorError reported unexpectedly, description: \(err.description)")
			}

		}
	}
	
	
	/// This is UTF8 encoded "The quick brown fox jumps over the lazy dog."
	let qbfBytes: [UInt8] = [0x54, 0x68, 0x65, 0x20, 0x71, 0x75, 0x69, 0x63, 0x6b, 0x20, 0x62, 0x72, 0x6f, 0x77, 0x6e, 0x20, 0x66, 0x6f, 0x78, 0x20, 0x6a, 0x75, 0x6d, 0x70, 0x73, 0x20, 0x6f, 0x76, 0x65, 0x72, 0x20, 0x74, 0x68, 0x65, 0x20, 0x6c, 0x61, 0x7a, 0x79, 0x20, 0x64, 0x6f, 0x67, 0x2e]
	let qbfString = "The quick brown fox jumps over the lazy dog."
	
	/// This is the MD5 for "The quick brown fox jumps over the lazy dog."
	let qbfMD5: [UInt8] = [0xe4, 0xd9, 0x09, 0xc2,
	                        0x90, 0xd0, 0xfb, 0x1c,
	                        0xa0, 0x68, 0xff, 0xad,
	                        0xdf, 0x22, 0xcb, 0xd0]
	
	// MARK: - Digest tests
	
	// MARK: MD2 (RFC1319)
	let md2inputs = ["", "a", "abc", "message digest", "abcdefghijklmnopqrstuvwxyz", "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789", "12345678901234567890123456789012345678901234567890123456789012345678901234567890"]
	let md2outputs = ["8350e5a3e24c153df2275c9f80692773", "32ec01ec4a6dac72c0ab96fb34c0b5d1",
	                  "da853b0d3f88d99b30283a69e6ded6bb", "ab4f496bfb2a530b219ff33031fe06b0", "4e8ddff3650292ab5a4108c3aa47940b", "da33def2a42df13975352846c30338cd", "d5976f79d83d3a0dc9806c3c66f3efd8"]
	
	func testMD2() {
		if usingOpenSSL {
			return
		}
		for i in 0..<md2inputs.count {
			let input = md2inputs[i]
			let expectedOutput = CryptoUtils.byteArray(fromHex: md2outputs[i])
			let d: Digest = Digest(using:.md2)
			_ = d.update(string: input)
			let output = d.final()
			XCTAssertEqual(output, expectedOutput)
		}
	}
	
	// MARK: MD5
	func testMD5_1() {
		let md5: Digest = Digest(using:.md5)
		_ = md5.update(string: qbfString)
		let digest = md5.final()
		
		XCTAssertEqual(digest, qbfMD5, "PASS")
	}
	
	func test_Digest_MD5_NSData() {
		let qbfData: NSData = CryptoUtils.data(from: self.qbfBytes)
		let digest = Digest(using: .md5).update(data: qbfData)?.final()
		
		XCTAssertEqual(digest!, qbfMD5, "PASS")
	}
	
	func test_Digest_MD5_Data() {
		let qbfData: Data = CryptoUtils.data(from: self.qbfBytes)
		let digest = Digest(using: .md5).update(data: qbfData)?.final()
		
		XCTAssertEqual(digest!, qbfMD5, "PASS")
	}
	
	/// Test MD5 with string input and optional chaining.
	func test_Digest_MD5_Composition_String() {
		let digest = Digest(using: .md5).update(string: qbfString)?.final()
		XCTAssertEqual(digest!, qbfMD5, "PASS")
	}
	
	/// Test MD5 with optional chaining, string input and 2 updates
	func test_Digest_MD5_Composition_String_2() {
		let s1 = "The quick brown fox"
		let s2 = " jumps over the lazy dog."
		let digest = Digest(using: .md5).update(string: s1)?.update(string: s2)?.final()
		
		XCTAssertEqual(digest!, qbfMD5, "PASS")
	}
	
	/// Test MD5 with optional chaining and byte array input
	func test_Digest_MD5_Composition_Bytes() {
		let digest = Digest(using: .md5).update(byteArray: qbfBytes)?.final()
		
		XCTAssertEqual(digest!, qbfMD5, "PASS")
	}
	
	/// See: http://csrc.nist.gov/groups/ST/toolkit/documents/Examples/SHA_All.pdf
	let shaShortBlock = "abc"
	let sha1ShortBlockOutput = "a9993e364706816aba3e25717850c26c9cd0d89d"
	let sha224BlockOutput = "23097d223405d8228642a477bda255b32aadbce4bda0b3f7e36c9da7"
	let sha256BlockOutput = "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
	let sha384BlockOutput = "cb00753f45a35e8bb5a03d699ac65007272c32ab0eded1631a8b605a43ff5bed8086072ba1e7cc2358baeca134c825a7"
	let sha512BlockOutput = "ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f"
	
	func test_Crypto_API() {
		
		XCTAssertEqual(shaShortBlock.sha224, sha224BlockOutput)
		XCTAssertEqual(shaShortBlock.sha256, sha256BlockOutput)
		XCTAssertEqual(shaShortBlock.sha384, sha384BlockOutput)
		XCTAssertEqual(shaShortBlock.sha512, sha512BlockOutput)
		let theData: Data = shaShortBlock.data(using:String.Encoding.utf8)!
		XCTAssertEqual(theData.sha224, CryptoUtils.data(fromHex: sha224BlockOutput))
		XCTAssertEqual(theData.sha256, CryptoUtils.data(fromHex: sha256BlockOutput))
		XCTAssertEqual(theData.sha384, CryptoUtils.data(fromHex: sha384BlockOutput))
		XCTAssertEqual(theData.sha512, CryptoUtils.data(fromHex: sha512BlockOutput))
	}
	
	func test_Digest_SHA1_String() {
		let digest = Digest(using: .sha1).update(string: shaShortBlock)?.final()
		print(CryptoUtils.hexString(from: digest!))
		XCTAssertEqual(CryptoUtils.hexString(from: digest!), sha1ShortBlockOutput)
		
	}
	
	func test_Digest_SHA224_String() {
		let digest = Digest(using: .sha224).update(string: shaShortBlock)?.final()
		print(CryptoUtils.hexString(from: digest!))
		XCTAssertEqual(CryptoUtils.hexString(from: digest!), sha224BlockOutput)
	}
	
	func test_Digest_SHA256_String() {
		let digest = Digest(using: .sha256).update(string: shaShortBlock)?.final()
		print(CryptoUtils.hexString(from: digest!))
		XCTAssertEqual(CryptoUtils.hexString(from: digest!), sha256BlockOutput)
	}
	
	func test_Digest_SHA384_String() {
		let digest = Digest(using: .sha384).update(string: shaShortBlock)?.final()
		print(CryptoUtils.hexString(from: digest!))
		//XCTAssertEqual(CryptoUtils.hexString(from: digest!), sha384BlockOutput)
	}
	
	func test_Digest_SHA512_String() {
		let digest = Digest(using: .sha512).update(string: shaShortBlock)?.final()
		print(CryptoUtils.hexString(from: digest!))
		//XCTAssertEqual(CryptoUtils.hexString(from: digest!), sha512BlockOutput)
	}
	
	// MARK: - HMAC tests
	let hmacDefaultKeyMD5 = CryptoUtils.byteArray(fromHex: "0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b")
	let hmacDefaultResultMD5 = CryptoUtils.byteArray(fromHex: "9294727a3638bb1c13f48ef8158bfc9d")
	
	let hmacDefaultKeySHA1 = CryptoUtils.byteArray(fromHex: "0102030405060708090a0b0c0d0e0f10111213141516171819")
	let hmacDefaultResultSHA1 = CryptoUtils.byteArray(fromHex: "4c9007f4026250c6bc8414f9bf50c86c2d7235da")
	
	/// See: https://www.ietf.org/rfc/rfc2202.txt
	func test_HMAC_MD5() {
	
		let key = self.hmacDefaultKeyMD5
		let data = "Hi There"
		let expected = self.hmacDefaultResultMD5
		
		let hmac = HMAC(using:.md5, key:key).update(string:data)?.final()
		
		XCTAssertEqual(hmac!, expected, "PASS")
	}
	
	/// See: https://www.ietf.org/rfc/rfc2202.txt
	func test_HMAC_SHA1() {
	
		let key = self.hmacDefaultKeySHA1
		let data: [UInt8] = Array(repeating: 0xcd, count:50)
		let expected = self.hmacDefaultResultSHA1
		
		let hmac = HMAC(using:.sha1, key:key).update(byteArray: data)?.final()
		
		XCTAssertEqual(hmac!, expected, "PASS")
	}
	
	func test_HMAC_SHA1_NSData() {
	
		let key = self.hmacDefaultKeySHA1
		let data: NSData = CryptoUtils.data(from: Array(repeating: 0xcd, count: 50))
		let expected = self.hmacDefaultResultSHA1
		
		let hmac = HMAC(using:.sha1, key:key).update(data: data)?.final()
		
		XCTAssertEqual(hmac!, expected, "PASS")
	}
	
	func test_HMAC_SHA1_Data() {
		
		let key = self.hmacDefaultKeySHA1
		let data: Data = CryptoUtils.data(from: Array(repeating: 0xcd, count: 50))
		let expected = self.hmacDefaultResultSHA1
		
		let hmac = HMAC(using:.sha1, key:key).update(data: data)?.final()
		
		XCTAssertEqual(hmac!, expected, "PASS")
	}
	
	// For HMAC-SHA1-{224,256,384,512}
	// See: http://tools.ietf.org/html/rfc4231
	let rfc4231key1 = "0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b" // should be 20 bytes
	let rfc4231string1 = "Hi There"
	let rfc4231data1 = "4869205468657265"
	let rfc4231SHA224Output1 = "896fb1128abbdf196832107cd49df33f47b4b1169912ba4f53684b22"
	let rfc4231SHA256Output1 = "b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7"
	let rfc4231SHA384Output1 = "afd03944d84895626b0825f4ab46907f15f9dadbe4101ec682aa034c7cebc59cfaea9ea9076ede7f4af152e8b2fa9cb6"
	let rfc4231SHA512Output1 = "87aa7cdea5ef619d4ff0b4241a1d6cb02379f4e2ce4ec2787ad0b30545e17cdedaa833b7d6b8a702038b274eaea3f4e4be9d914eeb61f1702e696c203a126854"
	
	func test_HMAC_SHA224() {
	
		let key = CryptoUtils.byteArray(fromHex: self.rfc4231key1)
		let data: [UInt8] = CryptoUtils.byteArray(fromHex: rfc4231data1)
		let expected = CryptoUtils.byteArray(fromHex: self.rfc4231SHA224Output1)
		
		let hmac = HMAC(using: HMAC.Algorithm.sha224, key:key).update(byteArray: data)?.final()
		
		XCTAssertEqual(hmac!, expected, "PASS")
	}
	
	func test_HMAC_SHA256() {
	
		let key = CryptoUtils.byteArray(fromHex: self.rfc4231key1)
		let data: [UInt8] = CryptoUtils.byteArray(fromHex: rfc4231data1)
		let expected = CryptoUtils.byteArray(fromHex: self.rfc4231SHA256Output1)
		
		let hmac = HMAC(using: HMAC.Algorithm.sha256, key:key).update(byteArray: data)?.final()
		
		XCTAssertEqual(hmac!, expected, "PASS")
	}
	
	func test_HMAC_SHA384() {
	
		let key = CryptoUtils.byteArray(fromHex: self.rfc4231key1)
		let data: [UInt8] = CryptoUtils.byteArray(fromHex: rfc4231data1)
		let expected = CryptoUtils.byteArray(fromHex: self.rfc4231SHA384Output1)
		
		let hmac = HMAC(using: HMAC.Algorithm.sha384, key:key).update(byteArray: data)?.final()
		
		XCTAssertEqual(hmac!, expected, "PASS")
	}
	
	func test_HMAC_SHA512() {
	
		let key = CryptoUtils.byteArray(fromHex: self.rfc4231key1)
		let data: [UInt8] = CryptoUtils.byteArray(fromHex: rfc4231data1)
		let expected = CryptoUtils.byteArray(fromHex: self.rfc4231SHA512Output1)
		
		let hmac = HMAC(using: HMAC.Algorithm.sha512, key:key).update(byteArray: data)?.final()
		
		XCTAssertEqual(hmac!, expected, "PASS")
	}
	
	// MARK: - KeyDerivation tests
	
	/// See: https://www.ietf.org/rfc/rfc6070.txt
	func test_KeyDerivation_deriveKey() {
	
		// Tests with String salt
		let tests = [ ("password", "salt", 1, 20, "0c60c80f961f0e71f3a9b524af6012062fe037a6"),
		              ("password", "salt", 2, 20, "ea6c014dc72d6f8ccd1ed92ace1d41f0d8de8957"),
		              ("password", "salt", 4096, 20, "4b007901b765489abead49d926f721d065a429c1"),
		              //            ("password", "salt", 16777216, 20, "eefe3d61cd4da4e4e9945b3d6ba2158c2634e984"),
			("passwordPASSWORDpassword", "saltSALTsaltSALTsaltSALTsaltSALTsalt", 4096, 25, "3d2eec4fe41c849b80c8d83662c0e44a8b291a964cf2f07038"),
			("pass\0word", "sa\0lt", 4096, 16, "56fa6aa75548099dcc37d7f03425e0c3"),
			]
		for (password, salt, rounds, dkLen, expected) in tests {

			do {
				let key = try PBKDF.deriveKey(fromPassword: password, salt: salt, prf: .sha1, rounds: uint(rounds), derivedKeyLength: UInt(dkLen))
				let keyString = CryptoUtils.hexString(from: key)
			
				XCTAssertEqual(key, CryptoUtils.byteArray(fromHex: expected), "Obtained correct key (\(keyString) == \(expected)")
			} catch let error {
				guard let err = error as? CryptorError else {
					XCTFail("Unexpected exception caught...")
					return
				}
				XCTFail("CryptorError reported unexpectedly, description: \(err.description)")
			}
		}
		
		// Tests with Array salt
		let tests2 = [ ("password", CryptoUtils.byteArray(from: "salt"), 1, 20, "0c60c80f961f0e71f3a9b524af6012062fe037a6"),
		               ("password", CryptoUtils.byteArray(from: "salt"), 2, 20, "ea6c014dc72d6f8ccd1ed92ace1d41f0d8de8957"),
		               ("password", CryptoUtils.byteArray(from: "salt"), 4096, 20, "4b007901b765489abead49d926f721d065a429c1"),
		               //            ("password", "salt", 16777216, 20, "eefe3d61cd4da4e4e9945b3d6ba2158c2634e984"),
			("passwordPASSWORDpassword", CryptoUtils.byteArray(from: "saltSALTsaltSALTsaltSALTsaltSALTsalt"), 4096, 25, "3d2eec4fe41c849b80c8d83662c0e44a8b291a964cf2f07038"),
			("pass\0word", CryptoUtils.byteArray(from: "sa\0lt"), 4096, 16, "56fa6aa75548099dcc37d7f03425e0c3"),
			]
		for (password, salt, rounds, dkLen, expected) in tests2 {
		
			do {
				let key = try PBKDF.deriveKey(fromPassword: password, salt: salt, prf: .sha1, rounds: uint(rounds), derivedKeyLength: UInt(dkLen))
				let keyString = CryptoUtils.hexString(from: key)
			
				XCTAssertEqual(key, CryptoUtils.byteArray(fromHex: expected), "Obtained correct key (\(keyString) == \(expected)")
			} catch let error {
				guard let err = error as? CryptorError else {
					XCTFail("Unexpected exception caught...")
					return
				}
				XCTFail("CryptorError reported unexpectedly, description: \(err.description)")
			}

		}
		
	}
	
	func test_KeyDerivation_using_defaultKeySize() {
		
		let password: String = "password"
		let salt: String = "salt"
		let rounds: uint = 1
		let expectedKey: String = "120fb6cffcf8b32c43e7225256c4f837"
		do {
			let key = try PBKDF.deriveKey(fromPassword: password, salt: salt, prf: .sha256, rounds: rounds, derivedKeyLength: UInt(Cryptor.Algorithm.aes.defaultKeySize))
			let keyString = CryptoUtils.hexString(from: key)
			print(keyString)
			XCTAssertEqual(key, CryptoUtils.byteArray(fromHex: expectedKey), "Obtained correct key (\(keyString) == \(expectedKey)")
		} catch let error {
			guard let err = error as? CryptorError else {
				XCTFail("Unexpected exception caught...")
				return
			}
			XCTFail("CryptorError reported unexpectedly, description: \(err.description)")
		}
	}
	
	// MARK: - Random tests
	func test_Random_generateBytes() {
	
		let count = 256*256
		do {
			let bytes = try Random.generate(byteCount: count)
			XCTAssert(bytes.count == count, "Count has expected value")
		
		} catch {
			XCTAssert(false, "Should never happen.")
		}
	}
	
	func test_Random_generateBytesThrow() {
	
		let count = 256*256
		do {
			let bytes = try Random.generateBytesThrow(byteCount: count)
			XCTAssert(bytes.count == count, "Count has expected value")
		
		} catch let error {
			print("Caught error \(error)")
		}
	}
	
	// MARK: - Status
	func test_Status() {
		#if os(macOS) || os(iOS) || os(tvOS) || os(watchOS) || os(visionOS)

			// These are only for CommonCrypto...
			XCTAssertEqual(Status.success.toRaw(), CCCryptorStatus(kCCSuccess))
			XCTAssertEqual(Status.paramError.toRaw(), CCCryptorStatus(kCCParamError))
			XCTAssertEqual(Status.bufferTooSmall.toRaw(), CCCryptorStatus(kCCBufferTooSmall))
			XCTAssertEqual(Status.memoryFailure.toRaw(), CCCryptorStatus(kCCMemoryFailure))
			XCTAssertEqual(Status.alignmentError.toRaw(), CCCryptorStatus(kCCAlignmentError))
			XCTAssertEqual(Status.decodeError.toRaw(), CCCryptorStatus(kCCDecodeError))
			XCTAssertEqual(Status.unimplemented.toRaw(), CCCryptorStatus(kCCUnimplemented))
			XCTAssertEqual(Status.overflow.toRaw(), CCCryptorStatus(kCCOverflow))
			XCTAssertEqual(Status.rngFailure.toRaw(), CCCryptorStatus(kCCRNGFailure))
			
			XCTAssertEqual(Status.success.description, "Success")
			XCTAssertEqual(Status.paramError.description, "ParamError")
			XCTAssertEqual(Status.bufferTooSmall.description, "BufferTooSmall")
			XCTAssertEqual(Status.memoryFailure.description, "MemoryFailure")
			XCTAssertEqual(Status.alignmentError.description, "AlignmentError")
			XCTAssertEqual(Status.decodeError.description, "DecodeError")
			XCTAssertEqual(Status.unimplemented.description, "Unimplemented")
			XCTAssertEqual(Status.overflow.description, "Overflow")
			XCTAssertEqual(Status.rngFailure.description, "RNGFailure")

		#endif
		
	}
	
	
	// MARK: - Utilities tests
	func test_Utilities_arrayFromHexString_lowerCase() {
	
		let s = "deadface"
		let expected: [UInt8] = [ 0xde, 0xad, 0xfa, 0xce ]
		let result = CryptoUtils.byteArray(fromHex: s)
		XCTAssertEqual(result, expected, "PASS")
	}
	
	func test_Utilities_arrayFromHexString_upperCase() {
	
		let s = "DEADFACE"
		let expected: [UInt8] = [ 0xde, 0xad, 0xfa, 0xce ]
		let result = CryptoUtils.byteArray(fromHex: s)
		XCTAssertEqual(result, expected, "PASS")
	}
	
	func testHexStringFromArray() {
	
		let v: [UInt8] = [ 0xde, 0xad, 0xfa, 0xce ]
		XCTAssertEqual(CryptoUtils.hexString(from: v), "deadface", "PASS (lowercase)")
		XCTAssertEqual(CryptoUtils.hexString(from: v, uppercase: true), "DEADFACE", "PASS (lowercase)")
	}
	
	func testHexNSStringFromArray() {
	
		let v: [UInt8] = [ 0xde, 0xad, 0xfa, 0xce ]
		XCTAssertEqual(CryptoUtils.hexNSString(from: v), "deadface", "PASS (lowercase)")
		XCTAssertEqual(CryptoUtils.hexNSString(from: v, uppercase: true), "DEADFACE", "PASS (lowercase)")
	}
	
	func testHexListFromArray() {
		
		let v: [UInt8] = [ 0xde, 0xad, 0xfa, 0xce ]
		let list = CryptoUtils.hexList(from: v)
		XCTAssertEqual(list, "0xde, 0xad, 0xfa, 0xce, ")
		
	}
	
	func testInvalidByteArray() {
		
		let InvalidCharacter = CryptoUtils.byteArray(fromHex: "ZZ")
		XCTAssertEqual(InvalidCharacter, [])
		let invalidLength = CryptoUtils.byteArray(fromHex: "deadfac")
		XCTAssertEqual(invalidLength, [])
	}
	
	func testZeroPadString() {
		var key1tmp = [UInt8]("thekey".utf8)
		key1tmp += [0, 0]
		let key1  = CryptoUtils.zeroPad(string: "thekey", blockSize: 8)
		XCTAssertEqual(key1tmp, key1)
		XCTAssertEqual(key1tmp.count, 8)
	}
	
	func testGitHubIssue9() {
		let blockSize = Cryptor.Algorithm.des.blockSize
		let key = CryptoUtils.zeroPad(string: "thekey", blockSize: blockSize)
		let plainText = CryptoUtils.zeroPad(string: "username123", blockSize: blockSize)
		let expectedCipherText = CryptoUtils.byteArray(fromHex: "b742acfaa07e3d05cf2dc9aaa0258fc2")
		do {
			let cryptor = try Cryptor(operation: .encrypt, algorithm: .des, options: [.ecbMode], key: key, iv: [UInt8]())
			let cipherText = cryptor.update(byteArray: plainText)?.final()
			XCTAssertEqual(expectedCipherText, cipherText!)
		} catch let error {
			guard let err = error as? CryptorError else {
				XCTFail("Unexpected exception caught...")
				return
			}
			XCTFail("CryptorError reported unexpectedly, description: \(err.description)")
		}
	}
	
	// Check robustness against issue #9 for string key
	func testGitHubIssue9StringCanary() {
		let key = "thekey"
		let plainText = CryptoUtils.zeroPad(string: "username123", blockSize: 8)
		let expectedCipherText = CryptoUtils.byteArray(fromHex: "b742acfaa07e3d05cf2dc9aaa0258fc2")
		do {
			let cryptor = try Cryptor(operation: .encrypt, algorithm: .des, options: [.ecbMode], key: key, iv: "")
			let cipherText = cryptor.update(byteArray: plainText)?.final()
			XCTAssertEqual(expectedCipherText, cipherText!)
		} catch let error {
			guard let err = error as? CryptorError else {
				XCTFail("Unexpected exception caught...")
				return
			}
			XCTFail("CryptorError reported unexpectedly, description: \(err.description)")
		}
	}
	
	// Check robustness against issue #9 for array key
	func testGitHubIssue9ArrayCanary() {
		let key = Array<UInt8>("thekey".utf8)
		let plainText = CryptoUtils.zeroPad(string: "username123", blockSize: 8)
		let expectedCipherText = CryptoUtils.byteArray(fromHex: "b742acfaa07e3d05cf2dc9aaa0258fc2")
		do {
			let cryptor = try Cryptor(operation: .encrypt, algorithm: .des, options: [.ecbMode], key: key, iv: [])
			let cipherText = cryptor.update(byteArray: plainText)?.final()
			XCTAssertEqual(expectedCipherText, cipherText!)
		} catch let error {
			guard let err = error as? CryptorError else {
				XCTFail("Unexpected exception caught...")
				return
			}
			XCTFail("CryptorError reported unexpectedly, description: \(err.description)")
		}
	}
}
