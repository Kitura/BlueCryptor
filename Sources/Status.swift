//
//  Status.swift
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
/// Links the native CommonCryptoStatus enumeration to Swiftier versions.
///
public enum Status : CCCryptorStatus, CustomStringConvertible, ErrorProtocol {

    /// Successful
    case Success,
    /// Parameter Error
    ParamError,
    /// Buffer too Small
    BufferTooSmall,
    /// Memory Failure
    MemoryFailure,
    /// Alignment Error
    AlignmentError,
    /// Decode Error
    DecodeError,
    /// Unimplemented
    Unimplemented,
    /// Overflow
    Overflow,
    /// Random Number Generator Err
    RNGFailure
    
    ///
    /// Converts this value to a native `CCCryptorStatus` value.
    ///
	public func toRaw() -> CCCryptorStatus {
		
        switch self {
			
        case Success:
			return CCCryptorStatus(kCCSuccess)
        case ParamError:
			return CCCryptorStatus(kCCParamError)
        case BufferTooSmall:
   			return CCCryptorStatus(kCCBufferTooSmall)
        case MemoryFailure:
			return CCCryptorStatus(kCCMemoryFailure)
        case AlignmentError:
   			return CCCryptorStatus(kCCAlignmentError)
        case DecodeError:
			return CCCryptorStatus(kCCDecodeError)
        case Unimplemented:
			return CCCryptorStatus(kCCUnimplemented)
        case Overflow:
			return CCCryptorStatus(kCCOverflow)
        case RNGFailure:
			return CCCryptorStatus(kCCRNGFailure)
        }
    }
    
    ///
    /// Human readable descriptions of the values. (Not needed in Swift 2.0?)
    ///
    static let descriptions = [ Success: "Success",
                                ParamError: "ParamError",
                                BufferTooSmall: "BufferTooSmall",
                                MemoryFailure: "MemoryFailure",
                                AlignmentError: "AlignmentError",
                                DecodeError: "DecodeError",
                                Unimplemented: "Unimplemented",
                                Overflow: "Overflow",
                                RNGFailure: "RNGFailure" ]
    
    ///
    /// Obtain human-readable string from enum value.
    ///
	public var description : String {
		
        return (Status.descriptions[self] != nil) ? Status.descriptions[self]! : ""
    }
    ///
    /// Create enum value from raw `CCCryptorStatus` value.
    ///
	public static func fromRaw(status : CCCryptorStatus) -> Status? {
		
        var from = [ kCCSuccess: Success,
                     kCCParamError: ParamError,
                     kCCBufferTooSmall: BufferTooSmall,
                     kCCMemoryFailure: MemoryFailure,
                     kCCAlignmentError: AlignmentError,
                     kCCDecodeError: DecodeError,
                     kCCUnimplemented: Unimplemented,
                     kCCOverflow: Overflow,
                     kCCRNGFailure: RNGFailure ]
        return from[Int(status)]
    
    }
}
