//
//  StreamCryptor.swift
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
/// Encrypts or decrypts return results as they become available.
///
/// - Note: The underlying cipher may be a block or a stream cipher.
///
///   Use for large files or network streams.
///
///   For small, in-memory buffers Cryptor may be easier to use.
///
public class StreamCryptor {
	
	#if os(Linux)
	
		//
		// Key sizes
		//
		static let kCCKeySizeAES128          = 16
		static let kCCKeySizeAES192          = 24
		static let kCCKeySizeAES256          = 32
		static let kCCKeySizeDES             = 8
		static let kCCKeySize3DES            = 24
		static let kCCKeySizeMinCAST         = 5
		static let kCCKeySizeMaxCAST         = 16
		static let kCCKeySizeMinRC2          = 1
		static let kCCKeySizeMaxRC2          = 128
		static let kCCKeySizeMinBlowfish     = 8
		static let kCCKeySizeMaxBlowfish     = 56
	
		//
		// Block sizes
		//
		static let kCCBlockSizeAES128        = 16
		static let kCCBlockSizeDES           = 8
		static let kCCBlockSize3DES          = 8
		static let kCCBlockSizeCAST          = 8
		static let kCCBlockSizeRC2           = 8
		static let kCCBlockSizeBlowfish      = 8
	
	#endif
	
    ///
    /// Enumerates Cryptor operations
    ///
    public enum Operation {

		/// Encrypting
        case Encrypt
		
		/// Decrypting
        case Decrypt
        
		#if os(OSX)
		
        	/// Convert to native `CCOperation`
	        func nativeValue() -> CCOperation {
			
    	        switch self {
				
        	    case Encrypt:
					return CCOperation(kCCEncrypt)
				
	            case Decrypt:
					return CCOperation(kCCDecrypt)
        	    }
	        }
		
		#elseif os(Linux)
		
			/// Convert to native value
			func nativeValue() -> UInt32 {
			
				switch self {
		
				case Encrypt:
					return 0
			
				case Decrypt:
					return 1
				}
			}
		
		#endif
    }
	
    ///
	/// Enumerates valid key sizes.
	///
    public enum ValidKeySize {
		
        case Fixed(Int)
        case Discrete([Int])
        case Range(Int,Int)
        
        ///
		///	Determines if a given `keySize` is valid for this algorithm.
		///
		/// - Parameter keySize: The size to test for validity.
		///
		/// - Returns: True if valid, false otherwise.
		///
        func isValidKeySize(keySize: Int) -> Bool {
			
            switch self {
				
            case .Fixed(let fixed):
				return (fixed == keySize)
				
            case .Range(let min, let max):
				return ((keySize >= min) && (keySize <= max))
				
            case .Discrete(let values):
				return values.contains(keySize)
            }
        }
        
        ///
		///	Determines the next valid key size; that is, the first valid key size larger
		///	than the given value.
		///
		/// - Parameter keySize: The size for which the `next` size is desired.
		///
		///	- Returns: Will return `nil` if the passed in `keySize` is greater than the max.
        ///
        func paddedKeySize(keySize: Int) -> Int? {
			
            switch self {
				
            case .Fixed(let fixed):
                return (keySize <= fixed) ? fixed : nil
				
            case .Range(let min, let max):
                return (keySize > max) ? nil : ((keySize < min) ? min : keySize)
				
			case .Discrete(let values):
                return values.sorted().reduce(nil) { answer, current in
                    return answer ?? ((current >= keySize) ? current : nil)
                }
            }
        }
        
        
    }
	
	///
	/// Maps CommonCryptoOptions onto a Swift struct.
	///
	public struct Options : OptionSet {
		
		public typealias RawValue = Int
		public let rawValue: RawValue
		
		/// Convert from a native value (i.e. `0`, `kCCOptionPKCS7Padding`, `kCCOptionECBMode`)
		public init(rawValue: RawValue) {
			self.rawValue = rawValue
		}
		
		/// Convert from a native value (i.e. `0`, `kCCOptionPKCS7Padding`, `kCCOptionECBMode`)
		public init(_ rawValue: RawValue) {
			self.init(rawValue: rawValue)
		}
		
		/// No options
		public static let None = Options(rawValue: 0)
		
		#if os(OSX)
		
			/// Use padding. Needed unless the input is a integral number of blocks long.
			public static var PKCS7Padding =  Options(rawValue:kCCOptionPKCS7Padding)
		
			/// Electronic Code Book Mode. Don't use this.
			public static var ECBMode = Options(rawValue:kCCOptionECBMode)
		
		#elseif os(Linux)
		
			/// Use padding. Needed unless the input is a integral number of blocks long.
			public static var PKCS7Padding =  Options(rawValue:0x0001)
		
			/// Electronic Code Book Mode. Don't use this.
			public static var ECBMode = Options(rawValue:0x0002)
		
		#endif
	}
	
    ///
    /// Enumerates available algorithms
    ///
    public enum Algorithm {
		
		#if os(OSX)
		
        /// Advanced Encryption Standard
		/// - Note: AES and AES128 are equivalent.
        case AES, AES128, AES192, AES256
		
        /// Data Encryption Standard
        case DES
		
        /// Triple DES
        case TripleDES
		
        /// CAST
        case CAST
		
        /// RC2
        case RC2
		
        /// Blowfish
        case Blowfish

		#elseif os(Linux)
		
		/// Advanced Encryption Standard
		/// - Note: AES and AES128 are equivalent.
		case AES, AES128, AES192, AES256
		
		/// Data Encryption Standard
		case DES
		
		/// Triple DES
		case TripleDES
		
		/// CAST
		case CAST
		
		/// RC2
		case RC2
		
		/// Blowfish
		case Blowfish
		
		#endif

        /// Blocksize, in bytes, of algorithm.
		public var blockSize: Int {
			
            switch self {
				
            case AES, AES128, AES192, AES256:
				return kCCBlockSizeAES128
				
            case DES:
				return kCCBlockSizeDES
				
            case TripleDES:
				return kCCBlockSize3DES
				
            case CAST:
				return kCCBlockSizeCAST
				
            case RC2:
				return kCCBlockSizeRC2
				
            case Blowfish:
				return kCCBlockSizeBlowfish
            }
        }
		
		#if os(OSX)
		
        /// Native, CommonCrypto constant for algorithm.
		func nativeValue() -> CCAlgorithm {
			
            switch self {
				
			case AES, AES128, AES192, AES256:
				return CCAlgorithm(kCCAlgorithmAES)
				
            case DES:
				return CCAlgorithm(kCCAlgorithmDES)
				
            case TripleDES:
				return CCAlgorithm(kCCAlgorithm3DES)
				
            case CAST:
				return CCAlgorithm(kCCAlgorithmCAST)
				
            case RC2:
				return CCAlgorithm(kCCAlgorithmRC2)
				
            case Blowfish:
				return CCAlgorithm(kCCAlgorithmBlowfish)
            }
        }
		
		#elseif os(Linux)
		
		/// Native, OpenSSL function for algorithm.
		func nativeValue(options: Options) -> UnsafePointer<EVP_CIPHER> {
			
			if options == .PKCS7Padding || options == .None {
			
				switch self {
					
				case AES, AES128:
					return EVP_aes_128_cbc()
		
				case AES256:
					return EVP_aes_256_cbc()
					
				case AES192:
					return EVP_aes_192_cbc()
					
				case DES:
					return EVP_des_cbc()
					
				case TripleDES:
					return EVP_des_ede3_cbc()
					
				case CAST:
					return EVP_cast5_cbc()
					
				case RC2:
					return EVP_rc2_cbc()
					
				case Blowfish:
					return EVP_bf_cbc()
				}
			}
			
			if options == .ECBMode {
				
				switch self {
					
				case AES, AES128:
					return EVP_aes_128_ecb()
		
				case AES256:
					return EVP_aes_256_ecb()
					
				case AES192:
					return EVP_aes_192_ecb()
					
				case DES:
					return EVP_des_ecb()
					
				case TripleDES:
					return EVP_des_ede3_ecb()
					
				case CAST:
					return EVP_cast5_ecb()
					
				case RC2:
					return EVP_rc2_ecb()
					
				case Blowfish:
					return EVP_bf_ecb()
				}
			}
		
			fatalError("Unsupported options and/or algorithm.")
		}
		
		#endif
		
		///
        /// Determines the valid key size for this algorithm
		///
		/// - Returns: Valid key size for this algorithm.
		///
        func validKeySize() -> ValidKeySize {
			
			#if os(OSX)
			
				switch self {
					
				case AES, AES128, AES192, AES256:
					return .Discrete([kCCKeySizeAES128, kCCKeySizeAES192, kCCKeySizeAES256])
					
				case DES:
					return .Fixed(kCCKeySizeDES)
					
				case TripleDES:
					return .Fixed(kCCKeySize3DES)
					
				case CAST:
					return .Range(kCCKeySizeMinCAST, kCCKeySizeMaxCAST)
					
				case RC2:
					return .Range(kCCKeySizeMinRC2, kCCKeySizeMaxRC2)
					
				case Blowfish:
					return .Range(kCCKeySizeMinBlowfish, kCCKeySizeMaxBlowfish)
				}
				
			#elseif os(Linux)
			
				switch self {
					
				case AES, AES128:
					return .Fixed(kCCKeySizeAES128)
					
				case AES192:
					return .Fixed(kCCKeySizeAES192)
					
				case AES256:
					return .Fixed(kCCKeySizeAES256)
					
				case DES:
					return .Fixed(kCCKeySizeDES)
					
				case TripleDES:
					return .Fixed(kCCKeySize3DES)
					
				case CAST:
					return .Range(kCCKeySizeMinCAST, kCCKeySizeMaxCAST)
					
				case RC2:
					return .Range(kCCKeySizeMinRC2, kCCKeySizeMaxRC2)
					
				case Blowfish:
					return .Range(kCCKeySizeMinBlowfish, kCCKeySizeMaxBlowfish)
				}
				
			#endif
        }
		
		///
        /// Tests if a given keySize is valid for this algorithm
		///
		/// - Parameter keySize: The key size to be validated.
		///
		/// - Returns: True if valid, false otherwise.
		///
        func isValidKeySize(keySize: Int) -> Bool {
            return self.validKeySize().isValidKeySize(keySize: keySize)
        }
		
		///
        /// Calculates the next, if any, valid keySize greater or equal to a given `keySize` for this algorithm
		///
		/// - Parameter keySize: Key size for which the next size is requested.
		///
		/// - Returns: Next key size or nil
		///
        func paddedKeySize(keySize: Int) -> Int? {
            return self.validKeySize().paddedKeySize(keySize: keySize)
        }
    }
	
    ///
    /// The status code resulting from the last method call to this Cryptor.
    ///    Used to get additional information when optional chaining collapes.
	///
    public internal(set) var status : Status = .Success

	#if os(OSX)
	
	/// CommonCrypto Context
	private var context = UnsafeMutablePointer<CCCryptorRef?>(allocatingCapacity: 1)
	
	#elseif os(Linux)
	
	/// OpenSSL Cipher Context
	private let context: UnsafeMutablePointer<EVP_CIPHER_CTX> = EVP_CIPHER_CTX_new()
	
	/// Operation
	private var operation: Operation = .Encrypt
	
	/// The algorithm
	private var algorithm: Algorithm
	
	#endif
	
	
	// MARK: Lifecycle Methods
	
	///
	///	Default Initializer
	///
	/// - Parameters: 
	///		- operation: 	The operation to perform see Operation (Encrypt, Decrypt)
	/// 	- algorithm: 	The algorithm to use see Algorithm (AES, DES, TripleDES, CAST, RC2, Blowfish)
	/// 	- keyBuffer: 	Pointer to key buffer
	/// 	- keyByteCount: Number of bytes in the key
	/// 	- ivBuffer: 	Initialization vector buffer
	///
	/// - Returns: New StreamCryptor instance.
	///
	public init(operation: Operation, algorithm: Algorithm, options: Options, keyBuffer: [UInt8], keyByteCount: Int, ivBuffer: UnsafePointer<UInt8>) {
		
		guard algorithm.isValidKeySize(keySize: keyByteCount) else {
			fatalError("FATAL_ERROR: Invalid key size.")
		}
		
		#if os(OSX)
		
			let rawStatus = CCCryptorCreate(operation.nativeValue(), algorithm.nativeValue(), CCOptions(options.rawValue), keyBuffer, keyByteCount, ivBuffer, context)
		
			if let status = Status.fromRaw(status: rawStatus) {
		
				self.status = status
		
			} else {
		
				fatalError("Cryptor init returned unexpected status.")
			}
		
		#elseif os(Linux)
		
			ERR_load_crypto_strings()
			
			self.algorithm = algorithm
			self.operation = operation
		
			var rawStatus: Int32
		
			switch self.operation {
			
			case .Encrypt:
				rawStatus = EVP_EncryptInit_ex(self.context, algorithm.nativeValue(options: options), nil, keyBuffer, ivBuffer)
		
			case .Decrypt:
				rawStatus = EVP_DecryptInit(self.context, algorithm.nativeValue(options: options), keyBuffer, ivBuffer)
			}
		
			if rawStatus == 0 {
			
				let errorCode = ERR_get_error()
				if let status = Status.fromRaw(status: errorCode) {
					self.status = status
				} else {
					fatalError("Cryptor init returned unexpected status.")
				}
			}
		
			// Default to no padding...
			var needPadding: Int32 = 0
			if options == .PKCS7Padding {
				needPadding = 1
			}
		
			// Note: This call must be AFTER the init call above...
			EVP_CIPHER_CTX_set_padding(self.context, needPadding);
		
			self.status = Status.Success
		
		#endif
		
	}
	
    ///
	///	Creates a new StreamCryptor
	///
	///	- Parameters:
 	///		- operation: 	The operation to perform see Operation (Encrypt, Decrypt)
	///		- algorithm: 	The algorithm to use see Algorithm (AES, DES, TripleDES, CAST, RC2, Blowfish)
	///		- key: 			A byte array containing key data
	///		- iv: 			A byte array containing initialization vector
    ///
	/// - Returns: New StreamCryptor instance.
	///
	public convenience init(operation: Operation, algorithm: Algorithm, options: Options, key: [UInt8], iv : [UInt8]) {
		
        guard let paddedKeySize = algorithm.paddedKeySize(keySize: key.count) else {
            fatalError("FATAL_ERROR: Invalid key size")
        }
        
        self.init(operation:operation,
                  algorithm:algorithm,
                  options:options,
                  keyBuffer:CryptoUtils.zeroPad(byteArray:key, blockSize: paddedKeySize),
                  keyByteCount:paddedKeySize,
                  ivBuffer:iv)
    }
	
    ///
	/// Creates a new StreamCryptor
	///
	///	- Parameters:
 	///		- operation: 	The operation to perform see Operation (Encrypt, Decrypt)
	///		- algorithm: 	The algorithm to use see Algorithm (AES, DES, TripleDES, CAST, RC2, Blowfish)
	///		- key: 			A string containing key data (will be interpreted as UTF8)
	///		- iv: 			A string containing initialization vector data (will be interpreted as UTF8)
    ///
	/// - Returns: New StreamCryptor instance.
	///
	public convenience init(operation: Operation, algorithm: Algorithm, options: Options, key: String, iv : String) {
		
        let keySize = key.utf8.count
        guard let paddedKeySize = algorithm.paddedKeySize(keySize: keySize) else {
            fatalError("FATAL_ERROR: Invalid key size")
        }
        
        self.init(operation:operation,
                  algorithm:algorithm,
                  options:options,
                  keyBuffer:CryptoUtils.zeroPad(string: key, blockSize: paddedKeySize),
                  keyByteCount:paddedKeySize,
                  ivBuffer:iv)
    }
	
	///
	/// Cleanup
	///
	deinit {
		
		#if os(OSX)
		
			let rawStatus = CCCryptorRelease(context.pointee)
			if let status = Status.fromRaw(status: rawStatus) {
			
				if status != .Success {
				
					NSLog("WARNING: CCCryptoRelease failed with status \(rawStatus).")
				}
			
			} else {
			
				fatalError("CCCryptorUpdate returned unexpected status.")
			}
			context.deallocateCapacity(1)
		
		#elseif os(Linux)

			EVP_CIPHER_CTX_free(self.context)
			ERR_free_strings()
		
		#endif
	}
	
	// MARK: Public Methods
	
    ///
	///	Add the contents of an NSData buffer to the current encryption/decryption operation.
    ///
	///	- Parameters:
 	///		- dataIn: 		The input data
	///		- byteArrayOut: Output data
	///
	///	- Returns: A tuple containing the number of output bytes produced and the status (see Status)
    ///
	public func update(dataIn: NSData, byteArrayOut: inout [UInt8]) -> (Int, Status) {
		
        let dataOutAvailable = byteArrayOut.count
        var dataOutMoved = 0
        update(bufferIn: UnsafePointer<UInt8>(dataIn.bytes), byteCountIn: dataIn.length, bufferOut: &byteArrayOut, byteCapacityOut: dataOutAvailable, byteCountOut: &dataOutMoved)
        return (dataOutMoved, self.status)
    }
	
    ///
	///	Add the contents of a byte array to the current encryption/decryption operation.
	///
	///	- Parameters:
 	///		- byteArrayIn: 	The input data
	///		- byteArrayOut: Output data
	///
	///	- Returns: A tuple containing the number of output bytes produced and the status (see Status)
    ///
	public func update(byteArrayIn: [UInt8], byteArrayOut: inout [UInt8]) -> (Int, Status) {
		
        let dataOutAvailable = byteArrayOut.count
        var dataOutMoved = 0
        update(bufferIn: byteArrayIn, byteCountIn: byteArrayIn.count, bufferOut: &byteArrayOut, byteCapacityOut: dataOutAvailable, byteCountOut: &dataOutMoved)
        return (dataOutMoved, self.status)
    }
	
    ///
	///	Add the contents of a string (interpreted as UTF8) to the current encryption/decryption operation.
	///
    /// - Parameters:
 	///		- byteArrayIn: 	The input data
	///		- byteArrayOut:	Output data
	///
	///	- Returns: A tuple containing the number of output bytes produced and the status (see Status)
    ///
	public func update(stringIn: String, byteArrayOut: inout [UInt8]) -> (Int, Status) {
		
        let dataOutAvailable = byteArrayOut.count
        var dataOutMoved = 0
        update(bufferIn: stringIn, byteCountIn: stringIn.utf8.count, bufferOut: &byteArrayOut, byteCapacityOut: dataOutAvailable, byteCountOut: &dataOutMoved)
        return (dataOutMoved, self.status)
    }
	
    ///
	///	Retrieves all remaining encrypted or decrypted data from this cryptor.
	///
	///	- Note: If the underlying algorithm is an block cipher and the padding option has
	/// not been specified and the cumulative input to the cryptor has not been an integral
	///	multiple of the block length this will fail with an alignment error.
	///
	///	- Note: This method updates the status property
	///
	///	- Parameter byteArrayOut: The output bffer
	///
	///	- Returns: a tuple containing the number of output bytes produced and the status (see Status)
    ///
	public func final(byteArrayOut: inout [UInt8]) -> (Int, Status) {
		
        let dataOutAvailable = byteArrayOut.count
        var dataOutMoved = 0
        final(bufferOut: &byteArrayOut, byteCapacityOut: dataOutAvailable, byteCountOut: &dataOutMoved)
        return (dataOutMoved, self.status)
    }
    
    // MARK: - Low-level interface
	
    ///
	///	Update the buffer
	///
	///	- Parameters: 
	///		- bufferIn: 		Pointer to input buffer
	///		- inByteCount: 		Number of bytes contained in input buffer
	///		- bufferOut: 		Pointer to output buffer
	///		- outByteCapacity: 	Capacity of the output buffer in bytes
	///		- outByteCount: 	On successful completion, the number of bytes written to the output buffer
	///
	///	- Returns: Status of the update
	///
	public func update(bufferIn: UnsafePointer<UInt8>, byteCountIn: Int, bufferOut: UnsafeMutablePointer<UInt8>, byteCapacityOut: Int, byteCountOut: inout Int) -> Status {
		
        if self.status == .Success {
			
			#if os(OSX)

	            let rawStatus = CCCryptorUpdate(context.pointee, bufferIn, byteCountIn, bufferOut, byteCapacityOut, &byteCountOut)
				if let status = Status.fromRaw(status: rawStatus) {
        	    	self.status =  status
				} else {
                	fatalError("CCCryptorUpdate returned unexpected status.")
            	}

			#elseif os(Linux)

				var rawStatus: Int32
				var outLength: Int32 = 0
			
				switch self.operation {
				
				case .Encrypt:
					rawStatus = EVP_EncryptUpdate(self.context, bufferOut, &outLength, bufferIn, Int32(byteCountIn))
					
				case .Decrypt:
					rawStatus = EVP_DecryptUpdate(self.context, bufferOut, &outLength, bufferIn, Int32(byteCountIn))
				}
			
				byteCountOut = Int(outLength)
			
				if rawStatus == 0 {
					
					let errorCode = ERR_get_error()
					if let status = Status.fromRaw(status: errorCode) {
						self.status = status
					} else {
						fatalError("Cryptor update returned unexpected status.")
					}
				
				} else {
					
					self.status = Status.Success
				}
			
			#endif

        }
		
        return self.status
    }
	
    ///
	///	Retrieves all remaining encrypted or decrypted data from this cryptor.
	///
	///	- Note: If the underlying algorithm is an block cipher and the padding option has
	///	not been specified and the cumulative input to the cryptor has not been an integral
	///	multiple of the block length this will fail with an alignment error.
    ///
	///	- Note: This method updates the status property
	///
	///	- Parameters:
 	///		- bufferOut: 		Pointer to output buffer
	///		- outByteCapacity: 	Capacity of the output buffer in bytes
	///		- outByteCount: 	On successful completion, the number of bytes written to the output buffer
	///
	///	- Returns: Status of the update
	///
	public func final(bufferOut: UnsafeMutablePointer<UInt8>, byteCapacityOut: Int, byteCountOut: inout Int) -> Status {
		
		if self.status == Status.Success {
			
			#if os(OSX)
			
	            let rawStatus = CCCryptorFinal(context.pointee, bufferOut, byteCapacityOut, &byteCountOut)
				if let status = Status.fromRaw(status: rawStatus) {
        	        self.status =  status
				} else {
	                fatalError("CCCryptorUpdate returned unexpected status.")
    	        }
			
			#elseif os(Linux)
			
				var rawStatus: Int32
				var outLength: Int32 = Int32(byteCapacityOut)
			
				switch self.operation {
				
				case .Encrypt:
					rawStatus = EVP_EncryptFinal(self.context, bufferOut, &outLength)
				
				case .Decrypt:
					rawStatus = EVP_DecryptFinal(self.context, bufferOut, &outLength)
				}
			
				byteCountOut = Int(outLength)
			
				if rawStatus == 0 {
				
					let errorCode = ERR_get_error()
					if let status = Status.fromRaw(status: errorCode) {
						self.status = status
					} else {
						fatalError("Cryptor final returned unexpected status.")
					}
				
				} else {
					
					self.status = Status.Success
				}
			
			#endif
        }
		
        return self.status
    }
	
    ///
	///	Determines the number of bytes that will be output by this Cryptor if inputBytes of additional
	///	data is input.
	///
	///	- Parameters:
 	///		- inputByteCount: 	Number of bytes that will be input.
	///		- isFinal: 			True if buffer to be input will be the last input buffer, false otherwise.
	///
	///	- Returns: The final output length
	///
	public func getOutputLength(inputByteCount: Int, isFinal: Bool = false) -> Int {
		
		#if os(OSX)

	        return CCCryptorGetOutputLength(context.pointee, inputByteCount, isFinal)

		#elseif os(Linux)
			
			if inputByteCount == 0 {
				return self.algorithm.blockSize
			}
		
			return (inputByteCount + self.algorithm.blockSize - (inputByteCount % self.algorithm.blockSize))
		
		#endif
    }
	
}
