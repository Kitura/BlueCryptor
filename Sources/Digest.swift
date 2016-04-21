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
import CommonCrypto

///
///	Public API for message digests.
///
/// Usage is straightforward
///
/// ```
/// let  s = "The quick brown fox jumps over the lazy dog."
/// var md5 : Digest = Digest(algorithm:.MD5)
/// md5.update(s)
/// let digest = md5.final()
///```
///
public class Digest : Updateable {
	
    ///
    /// The status of the Digest.
    /// For CommonCrypto this will always be `.Success`.
    /// It is here to provide for engines which can fail.
    ///
    public var status = Status.Success
    
    ///
    /// Enumerates available Digest algorithms
    ///
    public enum Algorithm  {
		
        /// Message Digest 2 See: http://en.wikipedia.org/wiki/MD2_(cryptography)
        case MD2,
        /// Message Digest 4
        MD4,
        /// Message Digest 5
        MD5,
        /// Secure Hash Algorithm 1
        SHA1,
        /// Secure Hash Algorithm 2 224-bit
        SHA224,
        /// Secure Hash Algorithm 2 256-bit
        SHA256,
        /// Secure Hash Algorithm 2 384-bit
        SHA384,
        /// Secure Hash Algorithm 2 512-bit
        SHA512
    }
    
    var engine: DigestEngine
	
    ///
    /// Create an algorithm-specific digest calculator
    ///   - parameter alrgorithm: the desired message digest algorithm
	///
    public init(algorithm: Algorithm) {
		
        switch algorithm {
        case .MD2:
            engine = DigestEngineCC<CC_MD2_CTX>(initializer:CC_MD2_Init, updater:CC_MD2_Update, finalizer:CC_MD2_Final, length:CC_MD2_DIGEST_LENGTH)
			
        case .MD4:
            engine = DigestEngineCC<CC_MD4_CTX>(initializer:CC_MD4_Init, updater:CC_MD4_Update, finalizer:CC_MD4_Final, length:CC_MD4_DIGEST_LENGTH)
			
        case .MD5:
            engine = DigestEngineCC<CC_MD5_CTX>(initializer:CC_MD5_Init, updater:CC_MD5_Update, finalizer:CC_MD5_Final, length:CC_MD5_DIGEST_LENGTH)
			
        case .SHA1:
            engine = DigestEngineCC<CC_SHA1_CTX>(initializer:CC_SHA1_Init, updater:CC_SHA1_Update, finalizer:CC_SHA1_Final, length:CC_SHA1_DIGEST_LENGTH)
			
        case .SHA224:
            engine = DigestEngineCC<CC_SHA256_CTX>(initializer:CC_SHA224_Init, updater:CC_SHA224_Update, finalizer:CC_SHA224_Final, length:CC_SHA224_DIGEST_LENGTH)
			
        case .SHA256:
            engine = DigestEngineCC<CC_SHA256_CTX>(initializer:CC_SHA256_Init, updater:CC_SHA256_Update, finalizer:CC_SHA256_Final, length:CC_SHA256_DIGEST_LENGTH)
			
        case .SHA384:
            engine = DigestEngineCC<CC_SHA512_CTX>(initializer:CC_SHA384_Init, updater:CC_SHA384_Update, finalizer:CC_SHA384_Final, length:CC_SHA384_DIGEST_LENGTH)
			
        case .SHA512:
            engine = DigestEngineCC<CC_SHA512_CTX>(initializer:CC_SHA512_Init, updater:CC_SHA512_Update, finalizer:CC_SHA512_Final, length:CC_SHA512_DIGEST_LENGTH)
        }
    }
	
    ///
	///	Low-level update routine. Updates the message digest calculation with
	///	the contents of a byte buffer.
	///
	///	- parameter buffer: the buffer
	///	- parameter the: number of bytes in buffer
	///	- returns: this Digest object (for optional chaining)
    ///
    public func update(buffer: UnsafePointer<Void>, byteCount: size_t) -> Self? {
		
        engine.update(buffer: buffer, byteCount: CC_LONG(byteCount))
        return self
    }
    
    ///
	///	Completes the calculate of the messge digest
	///	- returns: the message digest
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
protocol DigestEngine {

    func update(buffer: UnsafePointer<Void>,
                byteCount: CC_LONG)
    func final() -> [UInt8]
}

///
///	Wraps the underlying algorithm specific structures and calls
///	in a generic interface.
///
class DigestEngineCC<C> : DigestEngine {
	
    typealias Context = UnsafeMutablePointer<C>
    typealias Buffer = UnsafePointer<Void>
    typealias Digest = UnsafeMutablePointer<UInt8>
    typealias Initializer = (Context) -> (Int32)
    typealias Updater = (Context, Buffer, CC_LONG) -> (Int32)
    typealias Finalizer = (Digest, Context) -> (Int32)
    
    let context = Context(allocatingCapacity: 1)
    var initializer : Initializer
    var updater : Updater
    var finalizer : Finalizer
    var length : Int32
	
	///
	/// Default initializer
	///
	init(initializer : Initializer, updater : Updater, finalizer : Finalizer, length : Int32) {
		
        self.initializer = initializer
        self.updater = updater
        self.finalizer = finalizer
        self.length = length
        initializer(context)
    }
    
	deinit {
		
        context.deallocateCapacity(1)
    }
    
	func update(buffer: Buffer, byteCount: CC_LONG) {
		
        updater(context, buffer, byteCount)
    }
    
	func final() -> [UInt8] {
		
        let digestLength = Int(self.length)
		var digest = Array<UInt8>(repeating: 0, count:digestLength)
        finalizer(&digest, context)
        return digest
    }
}





