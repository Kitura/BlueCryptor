//
//  KeyDerivation.swift
//  Cryptor
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

import Foundation

#if os(OSX)
	import CommonCrypto
#elseif os(Linux)
	import CCrypto
#endif

///
/// Derives key material from a password or passphrase.
///
public class PBKDF {
	
    /// Enumerates available pseudo random algorithms
	public enum PseudoRandomAlgorithm {
		
        /// Secure Hash Algorithm 1
        case SHA1
		
        /// Secure Hash Algorithm 2 224-bit
        case SHA224
		
        /// Secure Hash Algorithm 2 256-bit
        case SHA256
		
        /// Secure Hash Algorithm 2 384-bit
        case SHA384
		
        /// Secure Hash Algorithm 2 512-bit
        case SHA512
		
		#if os(OSX)
			func nativeValue() -> CCPseudoRandomAlgorithm {
			
            	switch self {
		
	            case SHA1:
					return CCPseudoRandomAlgorithm(kCCPRFHmacAlgSHA1)
				case SHA224:
					return CCPseudoRandomAlgorithm(kCCPRFHmacAlgSHA224)
				case SHA256:
					return CCPseudoRandomAlgorithm(kCCPRFHmacAlgSHA256)
				case SHA384:
					return CCPseudoRandomAlgorithm(kCCPRFHmacAlgSHA384)
				case SHA512:
					return CCPseudoRandomAlgorithm(kCCPRFHmacAlgSHA512)
        	    }
        	}
		
		#elseif os(Linux)
		
			func nativeValue() -> UnsafePointer<EVP_MD> {
			
				switch self {
					
				case SHA1:
					return EVP_sha1()
				case .SHA224:
					return EVP_sha224()
				case .SHA256:
					return EVP_sha256()
				case .SHA384:
					return EVP_sha384()
				case .SHA512:
					return EVP_sha512()
				}
			}
		#endif
    }
	
    ///
    /// Determines the (approximate) number of iterations of the key derivation algorithm that need
    /// to be run to achieve a particular delay (or calculation time).
    ///
    /// - Parameters:
 	///		- passwordLength: password length in bytes
    /// 	- saltLength: salt length in bytes
    /// 	- algorithm: the PseudoRandomAlgorithm to use
    /// 	- derivedKeyLength: the desired key length
    /// 	- msec: the desired calculation time
	///
    /// - Returns: the number of times the algorithm should be run
    ///
	public class func calibrate(passwordLength: Int, saltLength: Int, algorithm: PseudoRandomAlgorithm, derivedKeyLength: Int, msec : UInt32) -> UInt {
		#if os(OSX)
	        return UInt(CCCalibratePBKDF(CCPBKDFAlgorithm(kCCPBKDF2), passwordLength, saltLength, algorithm.nativeValue(), derivedKeyLength, msec))
		#elseif os(Linux)
			// Value us per RFC 2898.
			return UInt(1000)
		#endif
    }
    

    /// 
    /// Derives key material from a password and salt.
    ///
    /// - Parameters:
 	///		- password: the password string, will be converted using UTF8
    /// 	- salt: the salt string will be converted using UTF8
    /// 	- prf: the pseudo random function
    /// 	- round: the number of rounds
    /// 	- derivedKeyLength: the length of the desired derived key, in bytes.
	///
    /// - Returns: the derived key
    ///
	public class func deriveKey(password: String, salt: String, prf:PseudoRandomAlgorithm, rounds: uint, derivedKeyLength: UInt) -> [UInt8] {
		
		var derivedKey = Array<UInt8>(repeating: 0, count:Int(derivedKeyLength))
		#if os(OSX)
			let status: Int32 = CCKeyDerivationPBKDF(CCPBKDFAlgorithm(kCCPBKDF2), password, password.lengthOfBytes(using: NSUTF8StringEncoding), salt, salt.lengthOfBytes(using:NSUTF8StringEncoding), prf.nativeValue(), rounds, &derivedKey, derivedKey.count)
			if status != Int32(kCCSuccess) {
			
    	        fatalError("ERROR: CCKeyDerivationPBDK failed with status \(status).")
        	}
		#elseif os(Linux)
			let status = PKCS5_PBKDF2_HMAC(password, Int32(password.lengthOfBytes(using: NSUTF8StringEncoding)), salt, Int32(salt.lengthOfBytes(using: NSUTF8StringEncoding)), Int32(rounds), prf.nativeValue(), Int32(derivedKey.count), &derivedKey)
			if status != 1 {
				fatalError("ERROR: PKCS5_PBKDF2_HMAC failed.")
			}
		#endif
        return derivedKey
    }
    
    ///
    /// Derives key material from a password and salt.
    ///
    /// - Parameters: 
	///		- password: the password string, will be converted using UTF8
    /// 	- salt: the salt array of bytes
    /// 	- prf: the pseudo random function
    /// 	- round: the number of rounds
    /// 	- derivedKeyLength: the length of the desired derived key, in bytes.
	///
    /// - Returns: the derived key
    ///
	public class func deriveKey(password : String, salt : [UInt8], prf: PseudoRandomAlgorithm, rounds: uint, derivedKeyLength: UInt) -> [UInt8] {
		
		var derivedKey = Array<UInt8>(repeating: 0, count:Int(derivedKeyLength))
		#if os(OSX)
			let status: Int32 = CCKeyDerivationPBKDF(CCPBKDFAlgorithm(kCCPBKDF2), password, password.lengthOfBytes(using: NSUTF8StringEncoding), salt, salt.count, prf.nativeValue(), rounds, &derivedKey, derivedKey.count)
			if status != Int32(kCCSuccess) {
	
	            fatalError("ERROR: CCKeyDerivationPBDK failed with status \(status).")
        	}
		#elseif os(Linux)
			let status = PKCS5_PBKDF2_HMAC(password, Int32(password.lengthOfBytes(using: NSUTF8StringEncoding)), salt, Int32(salt.count), Int32(rounds), prf.nativeValue(), Int32(derivedKey.count), &derivedKey)
			if status != 1 {
				fatalError("ERROR: PKCS5_PBKDF2_HMAC failed.")
			}
		#endif
        return derivedKey
    }
    
    ///
    /// Derives key material from a password buffer.
    ///
    /// - Parameters:
 	///		- password: pointer to the password buffer
    /// 	- passwordLength: password length in bytes
    /// 	- salt: pointer to the salt buffer
    /// 	- saltLength: salt length in bytes
    /// 	- prf: the PseudoRandomAlgorithm to use
    /// 	- rounds: the number of rounds of the algorithm to use
    /// 	- derivedKey: pointer to the derived key buffer.
    /// 	- derivedKeyLength: the desired key length
	///
    /// - Returns: the number of times the algorithm should be run
    ///
	public class func deriveKey(password: UnsafePointer<Int8>, passwordLen: Int, salt: UnsafePointer<UInt8>, saltLen: Int, prf: PseudoRandomAlgorithm, rounds: uint, derivedKey: UnsafeMutablePointer<UInt8>, derivedKeyLen: Int) {
		
		#if os(OSX)
        	let status: Int32 = CCKeyDerivationPBKDF(CCPBKDFAlgorithm(kCCPBKDF2), password, passwordLen, salt, saltLen, prf.nativeValue(), rounds, derivedKey, derivedKeyLen)
			if status != Int32(kCCSuccess) {
			
	            fatalError("ERROR: CCKeyDerivationPBDK failed with status \(status).")
    	    }
		#elseif os(Linux)
			let status = PKCS5_PBKDF2_HMAC(password, Int32(passwordLen), salt, Int32(saltLen), Int32(rounds), prf.nativeValue(), Int32(derivedKeyLen), derivedKey)
			if status != 1 {
				fatalError("ERROR: PKCS5_PBKDF2_HMAC failed.")
			}
		#endif
	}
}