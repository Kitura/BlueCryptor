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

#if os(OSX)
	import CommonCrypto
#elseif os(Linux)
	import CCrypto
#endif

#if os(OSX)
///
/// Links the native CommonCryptoStatus enumeration to Swift versions.
///
public enum Status: CCCryptorStatus, ErrorProtocol, CustomStringConvertible {

    /// Successful
    case Success
	
    /// Parameter Error
    case ParamError
	
    /// Buffer too Small
    case BufferTooSmall
	
    /// Memory Failure
    case MemoryFailure
	
    /// Alignment Error
    case AlignmentError
	
    /// Decode Error
    case DecodeError
	
    /// Unimplemented
    case Unimplemented
	
    /// Overflow
    case Overflow
	
    /// Random Number Generator Err
    case RNGFailure
    
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
	public var description: String {
		
        return (Status.descriptions[self] != nil) ? Status.descriptions[self]! : ""
    }

	///
    /// Create enum value from raw `CCCryptorStatus` value.
    ///
	public static func fromRaw(status: CCCryptorStatus) -> Status? {
		
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
	
#elseif os(Linux)
	
///
/// Error status
///
public enum Status: ErrorProtocol, CustomStringConvertible {
	
	/// Success
	case Success
	
	/// Unimplemented with reason
	case Unimplemented(String)
	
	/// Not supported with reason
	case NotSupported(String)
	
	/// Parameter Error
	case ParamError
	
	/// Failure with error code
 	case Fail(UInt)
	
	/// Random Byte Generator Failure with error code
	case RNGFailure(UInt)
	
	/// The error code itself
	public var code: Int {
		
		switch self {
			
		case Success:
			return 0
			
		case NotSupported:
			return -1
			
		case Unimplemented:
			return -2
			
		case ParamError:
			return -3
			
		case Fail(let code):
			return Int(code)
			
		case RNGFailure(let code):
			return Int(code)
		}
	}
	
	///
	/// Create enum value from raw `SSL error code` value.
	///
	public static func fromRaw(status: UInt) -> Status? {
		
		return Status.Fail(status)
	}
	
	///
	/// Obtain human-readable string for the error code.
	///
	public var description: String {
		
		switch self {
			
		case Success:
			return "No error"
			
		case NotSupported(let reason):
			return "Not supported: \(reason)"
			
		case Unimplemented(let reason):
			return "Not implemented: \(reason)"
			
		case .ParamError:
			return "Invalid parameters passed"
			
		case Fail(let errorCode):
			return "ERROR: code: \(errorCode), reason: \(ERR_error_string(UInt(errorCode), nil))"

		case RNGFailure(let errorCode):
			return "Random Byte Generator ERROR: code: \(errorCode), reason: \(ERR_error_string(UInt(errorCode), nil))"
		}
	}
}

//	MARK: Operators

func == (left: Status, right: Status) -> Bool {
	
	return left.code == right.code
}

func != (left: Status, right: Status) -> Bool {
	
	return left.code != right.code
}

#endif
