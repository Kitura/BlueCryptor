//
//  Utilities.swift
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
/// Various utility functions for conversions
///
public struct CryptoUtils {

	///
	/// Converts a single hexadecimal digit encoded as a Unicode Scalar to it's corresponding value.
	///
	/// - parameter c: A Unicode scalar in the set 0..9a..fA..F
	/// - returns: the hexadecimal value of the digit
	///
	static func convert(hexDigit c: UnicodeScalar) -> UInt8 {
		
		switch c {
			
		case UnicodeScalar(unicodeScalarLiteral:"0")...UnicodeScalar(unicodeScalarLiteral:"9"):
			return UInt8(c.value - UnicodeScalar(unicodeScalarLiteral:"0").value)
			
		case UnicodeScalar(unicodeScalarLiteral:"a")...UnicodeScalar(unicodeScalarLiteral:"f"):
			return UInt8(c.value - UnicodeScalar(unicodeScalarLiteral:"a").value + 0xa)
			
		case UnicodeScalar(unicodeScalarLiteral:"A")...UnicodeScalar(unicodeScalarLiteral:"F"):
			return UInt8(c.value - UnicodeScalar(unicodeScalarLiteral:"A").value + 0xa)
			
		default:
			fatalError("convertHexDigit: Invalid hex digit")
		}
	}
	
	///
	/// Converts a string of hexadecimal digits to a Swift array.
	///
	/// - parameter s: the hex string (must contain an even number of digits)
	/// - returns: a Swift array
	///
	public static func byteArray(fromHex string: String) -> [UInt8] {
		
		var g = string.unicodeScalars.makeIterator()
		var a : [UInt8] = []
		while let msn = g.next() {
			
			if let lsn = g.next() {
				
				a += [ (convert(hexDigit: msn) << 4 | convert(hexDigit: lsn)) ]
				
			} else {
				
				fatalError("arrayFromHexString: String must contain even number of characters")
			}
		}
		return a
	}
	
	///
	/// Converts a Swift UTF-8 String to a Swift array.
	///
	/// - parameter s: the string
	/// - returns: a Swift array
	///
	public static func byteArray(from string: String) -> [UInt8] {
		
		let array = [UInt8](string.utf8)
		return array
	}
	
	///
	/// Converts a string of hexadecimal digits to an `NSData` object.
	///
	/// - parameter s: the hex string (must contain an even number of digits)
	/// - returns: an NSData object
	///
	public static func data(fromHex string : String) -> NSData {
		
		let a = byteArray(fromHex: string)
		return NSData(bytes:a, length:a.count)
	}
	
	///
	/// Converts a Swift array to an `NSData` object.
	///
	/// - parameter a: the Swift array
	/// - returns: an NSData object
	///
	public static func data(from byteArray: [UInt8]) -> NSData {
		
		return NSData(bytes:byteArray, length:byteArray.count)
	}
	
	///
	/// Converts a Swift array to a string of hexadecimal digits.
	///
	/// - parameter a: the Swift array
	/// - parameter uppercase: if true use uppercase for letter digits, lowercase otherwise
	/// - returns: a Swift string
	///
	public static func hexString(from byteArray: [UInt8], uppercase: Bool = false) -> String {
		
		return byteArray.map() { String(format: (uppercase) ? "%02X" : "%02x", $0) }.reduce("", combine: +)
	}
	
	///
	/// Converts a Swift array to an `NSString` object.
	///
	/// - parameter a: the Swift array
	/// - parameter uppercase: if true use uppercase for letter digits, lowercase otherwise
	/// - returns: an `NSString` object
	///
	public static func hexNSString(from byteArray: [UInt8], uppercase: Bool = false) -> NSString {
		
		let formatString = (uppercase) ? "%02X" : "%02x"
		#if os(OSX)
			return byteArray.map() { String(format:formatString, $0) }.reduce("", combine: +)
		#else
			return byteArray.map() { String(format: formatString, $0) }.reduce("", combine: +).bridge()
		#endif
	}
	
	///
	/// Converts a Swift array to a Swift `String` containing a comma separated list of bytes.
	/// This is used to generate test data programmatically.
	///
	/// - parameter a: the Swift array
	/// - returns: a Swift string
	///
	public static func hexList(from byteArray : [UInt8]) -> String {
		
		return byteArray.map() { String(format:"0x%02x, ", $0) }.reduce("", combine: +)
	}
	
	///
	/// Zero pads a Swift array such that it is an integral number of `blockSizeinBytes` long.
	///
	/// - parameter a: the Swift array
	/// - parameter blockSizeInBytes: the block size in bytes (cunningly enough!)
	/// - returns: a Swift string
	///
	public static func zeroPad(byteArray: [UInt8], blockSize: Int) -> [UInt8] {
		
		let pad = blockSize - (byteArray.count % blockSize)
		guard pad != 0 else { return byteArray }
		return byteArray + Array<UInt8>(repeating: 0, count: pad)
	}
	
	///
	/// Zero pads a Swift string (after UTF8 conversion)  such that it is an integral number of `blockSizeinBytes` long.
	///
	/// - parameter s: the Swift array
	/// - parameter blockSizeInBytes: the block size in bytes (cunningly enough!)
	/// - returns: a Swift string
	///
	public static func zeroPad(string: String, blockSize: Int) -> [UInt8] {
		
		return zeroPad(byteArray: Array<UInt8>(string.utf8), blockSize: blockSize)
	}
	
}