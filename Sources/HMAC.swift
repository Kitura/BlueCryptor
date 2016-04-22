//
//  HMAC.swift
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
/// Calculates a cryptographic Hash-Based Message Authentication Code (HMAC).
///
public class HMAC : Updateable {
	
    ///
    /// Enumerates available algorithms.
    ///
    public enum Algorithm {
		
        /// Message Digest 5
        case MD5
		
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
		
			static let fromNative: [CCHmacAlgorithm: Algorithm] = [
		                                                      	CCHmacAlgorithm(kCCHmacAlgSHA1):.SHA1,
		                                                      	CCHmacAlgorithm(kCCHmacAlgSHA1):.MD5,
		                                                      	CCHmacAlgorithm(kCCHmacAlgSHA256):.SHA256,
		                                                      	CCHmacAlgorithm(kCCHmacAlgSHA384):.SHA384,
		                                                      	CCHmacAlgorithm(kCCHmacAlgSHA512):.SHA512,
		                                                      	CCHmacAlgorithm(kCCHmacAlgSHA224):.SHA224 ]
		
			static func fromNativeValue(nativeAlg: CCHmacAlgorithm) -> Algorithm? {
			
				return fromNative[nativeAlg]
			}
		
			func nativeValue() -> CCHmacAlgorithm {
			
				switch self {
				
				case .SHA1:
					return CCHmacAlgorithm(kCCHmacAlgSHA1)
				case .MD5:
					return CCHmacAlgorithm(kCCHmacAlgMD5)
				case .SHA224:
					return CCHmacAlgorithm(kCCHmacAlgSHA224)
				case .SHA256:
					return CCHmacAlgorithm(kCCHmacAlgSHA256)
				case .SHA384:
					return CCHmacAlgorithm(kCCHmacAlgSHA384)
				case .SHA512:
					return CCHmacAlgorithm(kCCHmacAlgSHA512)
				}
			}
		
		#elseif os(Linux)
		
			func nativeValue() -> UnsafePointer<EVP_MD> {
		
				switch self {
		
				case .SHA1:
					fatalError("SHA1 HMAC not supported by OpenSSL")
				case .MD5:
					return EVP_md5()
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
		
        ///
        /// Obtains the digest length produced by this algorithm (in bytes).
        ///
        public func digestLength() -> Int {
			
			#if os(OSX)
				
				switch self {
					
				case .SHA1:
					return Int(CC_SHA1_DIGEST_LENGTH)
				case .MD5:
					return Int(CC_MD5_DIGEST_LENGTH)
				case .SHA224:
					return Int(CC_SHA224_DIGEST_LENGTH)
				case .SHA256:
					return Int(CC_SHA256_DIGEST_LENGTH)
				case .SHA384:
					return Int(CC_SHA384_DIGEST_LENGTH)
				case .SHA512:
					return Int(CC_SHA512_DIGEST_LENGTH)
				}
				
			#elseif os(Linux)
				
				switch self {
					
				case .SHA1:
					fatalError("SHA1 HMAC not supported by OpenSSL")
				case .MD5:
					return Int(MD5_DIGEST_LENGTH)
				case .SHA224:
					return Int(SHA224_DIGEST_LENGTH)
				case .SHA256:
					return Int(SHA256_DIGEST_LENGTH)
				case .SHA384:
					return Int(SHA384_DIGEST_LENGTH)
				case .SHA512:
					return Int(SHA512_DIGEST_LENGTH)
				}
			#endif
			
        }
    }
	
	#if os(OSX)
    	typealias Context = UnsafeMutablePointer<CCHmacContext>
	#elseif os(Linux)
		typealias Context = UnsafeMutablePointer<HMAC_CTX>
	#endif
    
    /// Status of the calculation
    public var status: Status = .Success
    
    let context = Context(allocatingCapacity: 1)
    var algorithm: Algorithm
    
	// MARK: Lifecycle Methods
	
	///
	/// Creates a new HMAC instance with the specified algorithm and key.
	///
	/// - Parameters:
 	///		- algorithm: 	selects the algorithm
	/// 	- keyBuffer: 	specifies the key
	///		- keyByteCount: number of bytes on keyBuffer
	///
	init(algorithm: Algorithm, keyBuffer: UnsafePointer<Void>, keyByteCount: Int) {
		
        self.algorithm = algorithm
		#if os(OSX)
	        CCHmacInit(context, algorithm.nativeValue(), keyBuffer, size_t(keyByteCount))
		#elseif os(Linux)
			HMAC_Init(context, keyBuffer, Int32(keyByteCount), algorithm.nativeValue())
		#endif
    }
    
    ///
    /// Creates a new HMAC instance with the specified algorithm and key.
    ///
    /// - Parameters:
 	///		- algorithm: 	selects the algorithm
    /// 	- key: 			specifies the key
    ///
	public init(algorithm: Algorithm, key: NSData) {
		
        self.algorithm = algorithm
		#if os(OSX)
        	CCHmacInit(context, algorithm.nativeValue(), key.bytes, size_t(key.length))
		#elseif os(Linux)
			HMAC_Init(context, key.bytes, Int32(key.length), algorithm.nativeValue())
		#endif
    }
    
    ///
    /// Creates a new HMAC instance with the specified algorithm and key.
    ///
    /// - Parameters:
 	///		- algorithm: 	selects the algorithm
    /// 	- key: 			specifies the key
    ///
	public init(algorithm: Algorithm, key: [UInt8]) {
		
        self.algorithm = algorithm
		#if os(OSX)
        	CCHmacInit(context, algorithm.nativeValue(), key, size_t(key.count))
		#elseif os(Linux)
			HMAC_Init(context, key, Int32(key.count), algorithm.nativeValue())
		#endif
    }
    
    ///
    /// Creates a new HMAC instance with the specified algorithm and key string.
    /// The key string is converted to bytes using UTF8 encoding.
    ///
    /// - Parameters:
 	///		- algorithm: 	selects the algorithm
    /// 	- key: 			specifies the key
    ///
	public init(algorithm: Algorithm, key: String) {
		
        self.algorithm = algorithm
		#if os(OSX)
        	CCHmacInit(context, algorithm.nativeValue(), key, size_t(key.lengthOfBytes(using: NSUTF8StringEncoding)))
		#elseif os(Linux)
			HMAC_Init(context, key, Int32(key.lengthOfBytes(using: NSUTF8StringEncoding)), algorithm.nativeValue())
		#endif
    }
	
	///
	/// Cleanup
	///
    deinit {
        context.deallocateCapacity(1)
    }
 
	// MARK: Public Methods
	
    ///
    /// Updates the calculation of the HMAC with the contents of a buffer.
	///
	/// - Parameter buffer: update buffer
    ///
    /// - Returns: the calculated HMAC
    ///
	public func update(buffer: UnsafePointer<Void>, byteCount: size_t) -> Self? {
		
		#if os(OSX)
	        CCHmacUpdate(context, buffer, byteCount)
		#elseif os(Linux)
			HMAC_Update(context, UnsafePointer<UInt8>(buffer), byteCount)
		#endif
        return self
    }
    
    ///
    /// Finalizes the HMAC calculation
    ///
    /// - Returns: the calculated HMAC
    ///
	public func final() -> [UInt8] {
		
		var hmac = Array<UInt8>(repeating: 0, count:algorithm.digestLength())
		#if os(OSX)
        	CCHmacFinal(context, &hmac)
		#elseif os(Linux)
			var length: UInt32 = 0
			HMAC_Final(context, &hmac, &length)
		#endif
        return hmac
    }
}

