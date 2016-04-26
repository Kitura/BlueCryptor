//
//  Crypto.swift
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

///
/// Implements a simplified API for calculating digests over single buffers
///
public protocol CryptoDigest {
	
    /// Calculates a message digest
    func digest(algorithm: Digest.Algorithm) -> Self
}

///
/// Extension to the CryptoDigest to return the digest appropriate to the selected algorithm.
///
extension CryptoDigest {
	
    /// An MD2 digest of this object
    public var MD2: Self {
		return self.digest(algorithm: .MD2)
	}
	
    /// An MD4 digest of this object
    public var MD4: Self {
		return self.digest(algorithm: .MD4)
	}
	
    /// An MD5 digest of this object
    public var MD5: Self {
		return self.digest(algorithm: .MD5)
 	}
	
    /// An SHA1 digest of this object
    public var SHA1: Self {
		return self.digest(algorithm: .SHA1)
	}
	
    /// An SHA224 digest of this object
    public var SHA224: Self {
		return self.digest(algorithm: .SHA224)
	}
	
    /// An SHA256 digest of this object
    public var SHA256: Self {
		return self.digest(algorithm: .SHA256)
	}
	
    /// An SHA384 digest of this object
    public var SHA384: Self {
		return self.digest(algorithm: .SHA384)
	}
	
    /// An SHA512 digest of this object
    public var SHA512: Self {
		return self.digest(algorithm: .SHA512)
	}
}

///
/// Extension for NSData to return an NSData object containing the digest.
///
extension NSData: CryptoDigest {	
    ///
    /// Calculates the Message Digest for this data.
    /// 
    /// - Parameter algorithm: the digest algorithm to use
	///
    /// - Returns: an `NSData` object containing the message digest
    ///
    public func digest(algorithm: Digest.Algorithm) -> Self {
		
        // This force unwrap may look scary but for CommonCrypto this cannot fail.
        // The API allows for optionals to support the OpenSSL implementation which can.
		let result = (Digest(algorithm: algorithm).update(data: self)?.final())!
        let data = self.dynamicType.init(bytes: result, length: result.count)
        return data
    }
}

///
/// Extension for String to return a String containing the digest.
///
extension String : CryptoDigest {
    ///
    /// Calculates the Message Digest for this string.
    /// The string is converted to raw data using UTF8.
    ///
    /// - Parameter algorithm: the digest algorithm to use
	///
    /// - Returns: a hex string of the calculated digest
    ///
    public func digest(algorithm: Digest.Algorithm) -> String {
        // This force unwrap may look scary but for CommonCrypto this cannot fail.
        // The API allows for optionals to support the OpenSSL implementation which can.
		let result = (Digest(algorithm: algorithm).update(string: self as String)?.final())!
		return CryptoUtils.hexString(from: result)
    }
}
