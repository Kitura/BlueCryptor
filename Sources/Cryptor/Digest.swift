//
//  Digest.swift
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

#if os(Linux)
    import OpenSSL
    typealias CC_LONG = size_t
#else
    import CommonCrypto
    #if canImport(CryptoKit)
        import CryptoKit
    #endif
#endif

///
///	Public API for message digests.
///
/// Usage is straightforward
///
/// ```
/// let  s = "The quick brown fox jumps over the lazy dog."
/// var md5: Digest = Digest(using:.md5)
/// md5.update(s)
/// let digest = md5.final()
///```
///
public class Digest: Updatable {
	
    ///
    /// The status of the Digest.
    /// For CommonCrypto this will always be `.Success`.
    /// It is here to provide for engines which can fail.
    ///
    public var status = Status.success
    
    ///
    /// Enumerates available Digest algorithms
    ///
    public enum Algorithm {
		
        // Only available on Linux as Apple platforms consider them cryptographically insecure
        #if os(Linux)
            /// Message Digest 4
            case md4
            
            /// Message Digest 5
            case md5
        #endif
        
        /// Message Digest 5
        /// - NOTE: Do NOT use for cryptography, considered insecure
        case md5_insecure
        
        /// Secure Hash Algorithm 1
        case sha1
        
        /// Secure Hash Algorithm 1
        /// - NOTE: Do NOT use for cryptography, considered insecure
        case sha1_insecure
        
        /// Secure Hash Algorithm 2 224-bit
        case sha224
		
        /// Secure Hash Algorithm 2 256-bit
        case sha256
		
        /// Secure Hash Algorithm 2 384-bit
        case sha384
		
        /// Secure Hash Algorithm 2 512-bit
        case sha512
    }
    
    private var engine: DigestEngine
	
    ///
    /// Create an algorithm-specific digest calculator
	///
    /// - Parameter alrgorithm: the desired message digest algorithm
	///
    public init(using algorithm: Algorithm) {
		
        switch algorithm {
        
        #if os(Linux)
            case .md4:
                self.engine = DigestEngineCC<MD4_CTX>(initializer:MD4_Init, updater:MD4_Update, finalizer:MD4_Final, length:MD4_DIGEST_LENGTH)
                
            case .md5, .md5_insecure:
                self.engine = DigestEngineCC<MD5_CTX>(initializer:MD5_Init, updater:MD5_Update, finalizer:MD5_Final, length:MD5_DIGEST_LENGTH)
                        
        #else
			
            case .md5_insecure:
                self.engine = DigestEngineMD5Insecure()

        #endif
            
        case .sha1:
            #if os(Linux)
                self.engine = DigestEngineCC<SHA_CTX>(initializer:SHA1_Init, updater:SHA1_Update, finalizer:SHA1_Final, length:SHA_DIGEST_LENGTH)
            #else
                engine = DigestEngineCC<CC_SHA1_CTX>(initializer:CC_SHA1_Init, updater:CC_SHA1_Update, finalizer:CC_SHA1_Final, length:CC_SHA1_DIGEST_LENGTH)
            #endif
            
        case .sha1_insecure:
            #if os(Linux)
                self.engine = DigestEngineCC<SHA_CTX>(initializer:SHA1_Init, updater:SHA1_Update, finalizer:SHA1_Final, length:SHA_DIGEST_LENGTH)
            #else
                self.engine = DigestEngineSHA1Insecure()
            #endif
            
        case .sha224:
            #if os(Linux)
                self.engine = DigestEngineCC<SHA256_CTX>(initializer:SHA224_Init, updater:SHA224_Update, finalizer:SHA224_Final, length:SHA224_DIGEST_LENGTH)
            #else
                self.engine = DigestEngineCC<CC_SHA256_CTX>(initializer:CC_SHA224_Init, updater:CC_SHA224_Update, finalizer:CC_SHA224_Final, length:CC_SHA224_DIGEST_LENGTH)
			#endif
			
        case .sha256:
            #if os(Linux)
                self.engine = DigestEngineCC<SHA256_CTX>(initializer: SHA256_Init, updater:SHA256_Update, finalizer:SHA256_Final, length:SHA256_DIGEST_LENGTH)
            #else
                self.engine = DigestEngineCC<CC_SHA256_CTX>(initializer:CC_SHA256_Init, updater:CC_SHA256_Update, finalizer:CC_SHA256_Final, length:CC_SHA256_DIGEST_LENGTH)
			#endif
			
        case .sha384:
            #if os(Linux)
                self.engine = DigestEngineCC<SHA512_CTX>(initializer:SHA384_Init, updater:SHA384_Update, finalizer:SHA384_Final, length:SHA384_DIGEST_LENGTH)
            #else
                self.engine = DigestEngineCC<CC_SHA512_CTX>(initializer:CC_SHA384_Init, updater:CC_SHA384_Update, finalizer:CC_SHA384_Final, length:CC_SHA384_DIGEST_LENGTH)
			#endif
			
        case .sha512:
            #if os(Linux)
                self.engine = DigestEngineCC<SHA512_CTX>(initializer:SHA512_Init, updater:SHA512_Update, finalizer:SHA512_Final, length:SHA512_DIGEST_LENGTH)
            #else
                self.engine = DigestEngineCC<CC_SHA512_CTX>(initializer:CC_SHA512_Init, updater:CC_SHA512_Update, finalizer:CC_SHA512_Final, length:CC_SHA512_DIGEST_LENGTH)
			#endif
        }
    }
	
    ///
	///	Low-level update routine. Updates the message digest calculation with
	///	the contents of a byte buffer.
	///
	/// - Parameters:
 	///		- buffer:		The buffer
	///		- byteCount: 	Number of bytes in buffer
	///
	/// - Returns: This Digest object (for optional chaining)
    ///
    public func update(from buffer: UnsafeRawPointer, byteCount: size_t) -> Self? {
		
        engine.update(buffer: buffer, byteCount: CC_LONG(byteCount))
        return self
    }
    
    ///
	///	Completes the calculate of the messge digest
	///
	/// - Returns: The message digest
	///
	public func final() -> [UInt8] {
		
        return engine.final()
    }
}

// MARK: Internal Classes

///
/// Defines the interface between the Digest class and an
/// algorithm specific DigestEngine
///
private protocol DigestEngine {

	///
	/// Update method
	///
	/// - Parameters:
	///		- buffer:		The buffer to add.
	///		- byteCount:	The length of the buffer.
	///
    func update(buffer: UnsafeRawPointer, byteCount: CC_LONG)
	
	///
	/// Finalizer routine
	///
	/// - Returns: Byte array containing the digest.
	///
    func final() -> [UInt8]
}

///
///	Wraps the underlying algorithm specific structures and calls
///	in a generic interface.
///
/// - Parameter CTX:	The context for the digest.
///
private class DigestEngineCC<CTX>: DigestEngine {
	
    typealias Context = UnsafeMutablePointer<CTX>
    typealias Buffer = UnsafeRawPointer
    typealias Digest = UnsafeMutablePointer<UInt8>
    typealias Initializer = (Context) -> (Int32)
    typealias Updater = (Context, Buffer, CC_LONG) -> (Int32)
    typealias Finalizer = (Digest, Context) -> (Int32)
    
    let context = Context.allocate(capacity: 1)
    var initializer: Initializer
    var updater: Updater
    var finalizer: Finalizer
    var length: Int32
	
	///
	/// Default initializer
	///
	/// - Parameters:
	///		- initializer: 	The digest initializer routine.
	/// 	- updater:		The digest updater routine.
	/// 	- finalizer:	The digest finalizer routine.
	/// 	- length:		The digest length.
	///
	init(initializer: @escaping Initializer, updater: @escaping Updater, finalizer: @escaping Finalizer, length: Int32) {
		
        self.initializer = initializer
        self.updater = updater
        self.finalizer = finalizer
        self.length = length
        _ = initializer(context)
    }
	
	///
	/// Cleanup
	///
	deinit {
		context.deallocate()
	}
	
	///
	/// Update method
	///
	/// - Parameters:
	///		- buffer:		The buffer to add.
	///		- byteCount:	The length of the buffer.
	///
	func update(buffer: Buffer, byteCount: CC_LONG) {
		
        _ = updater(context, buffer, byteCount)
    }
    
	///
	/// Finalizer routine
	///
	/// - Returns: Byte array containing the digest.
	///
	func final() -> [UInt8] {
		
        let digestLength = Int(self.length)
		var digest = Array<UInt8>(repeating: 0, count:digestLength)
        _ = finalizer(&digest, context)
        return digest
    }
}


#if !os(Linux)

/**
 Wraps the Insecure.MD5 engine as a DigestEngine
 */
private class DigestEngineMD5Insecure: DigestEngine {
    var engine = Insecure.MD5()
    
    func update(buffer: UnsafeRawPointer, byteCount: CC_LONG) {
        guard byteCount<=Int.max else {
            fatalError("Cannot support byte count of size: \(byteCount)")
        }
        let count = Int(byteCount)
        let bufferPointer = UnsafeRawBufferPointer(start: buffer, count: count)
        engine.update(bufferPointer: bufferPointer)
    }
    
    func final() -> [UInt8] {
        let digest: Insecure.MD5Digest = self.engine.finalize()
        let digestLength = Int(Insecure.MD5Digest.byteCount)
        var buffer = Array<UInt8>(repeating: 0, count:digestLength)
        digest.withUnsafeBytes { (rawBuffer: UnsafeRawBufferPointer) in
            for (index, val) in rawBuffer.enumerated() {
                buffer[index] = val
            }
        }
        return buffer
    }
}

/**
 Wraps the Insecure.SHA1 engine as a DigestEngine
 */
private class DigestEngineSHA1Insecure: DigestEngine {
    var engine = Insecure.SHA1()
    
    func update(buffer: UnsafeRawPointer, byteCount: CC_LONG) {
        guard byteCount<=Int.max else {
            fatalError("Cannot support byte count of size: \(byteCount)")
        }
        let count = Int(byteCount)
        let bufferPointer = UnsafeRawBufferPointer(start: buffer, count: count)
        engine.update(bufferPointer: bufferPointer)
    }
    
    func final() -> [UInt8] {
        let digest: Insecure.SHA1Digest = self.engine.finalize()
        let digestLength = Int(Insecure.SHA1Digest.byteCount)
        var buffer = Array<UInt8>(repeating: 0, count:digestLength)
        digest.withUnsafeBytes { (rawBuffer: UnsafeRawBufferPointer) in
            for (index, val) in rawBuffer.enumerated() {
                buffer[index] = val
            }
        }
        return buffer
    }
}

#endif
