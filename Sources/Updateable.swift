//
//  Updateable.swift
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
/// A protocol for calculations that can be updated with incremental data buffers.
///
public protocol Updateable {
	
    /// Status of the calculation.
    var status : Status { get }
	
	///
    /// Low-level update routine.
    /// Updates the calculation with the contents of a data buffer.
    /// - parameter buffer: pointer to the data buffer 
    /// - parameter byteCount: length of the buffer in bytes
    /// - returns: self if no error for optional chaining, null otherwise
	///
    func update(buffer: UnsafePointer<Void>, byteCount: size_t) -> Self?
}

///
/// Factors out common update code from Digest, HMAC and Cryptor.
///
extension Updateable {
    ///
    /// Updates the current calculation with data contained in an `NSData` object.
    ///
    /// - parameters data: the data buffer
    ///
	public func update(data: NSData) -> Self? {
		
        update(buffer: data.bytes, byteCount: size_t(data.length))
        return self.status == Status.Success ? self : nil
    }
	
    ///
    /// Updates the current calculation with data contained in a Swift array.
    ///
    /// - parameters byteArray: the Swift array
    ///
	public func update(byteArray: [UInt8]) -> Self? {
		
        update(buffer: byteArray, byteCount: size_t(byteArray.count))
        return self.status == Status.Success ? self : nil
    }
	
    ///
    /// Updates the current calculation with data contained in a Swift string.
    /// The corresponding data will be generated using UTF8 encoding.
    ///
    /// - parameters string: the Swift string
    ///
	public func update(string: String) -> Self? {
		
        update(buffer: string, byteCount: size_t(string.lengthOfBytes(using: NSUTF8StringEncoding)))
        return self.status == Status.Success ? self : nil
    }
}