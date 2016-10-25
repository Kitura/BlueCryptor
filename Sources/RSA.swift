//
//  RSA.swift
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

//
// Below are swiftlint disabled rules:
// swiftlint:disable trailing_newline
// swiftlint:disable force_cast
// swiftlint:disable variable_name_min_length
// swiftlint:disable function_body_length
// swiftlint:disable variable_name
// swiftlint:disable variable_name_max_length
// swiftlint:disable line_length
// swiftlint:disable trailing_whitespace
// swiftlint:disable type_name
// swiftlint:disable type_body_length
// swiftlint:disable todo
// swiftlint:disable file_length
// swiftlint:disable leading_whitespace
// swiftlint:disable mark
// swiftlint:disable function_parameter_count
// swiftlint:disable cyclomatic_complexity
//

import Foundation

#if os(macOS) || os(iOS) || os(tvOS) || os(watchOS)
	import CommonCrypto
	import Security
#elseif os(Linux)
	import OpenSSL
#endif

///
/// RSA Handling: Implemnents a series of Class Level RSA Helper Functions.
///
public class RSA {
	
	// MARK: Enums
	
	#if os(macOS) || os(iOS) || os(tvOS) || os(watchOS)

		/// The RSA Algorithm to use.
		public enum RSAAlgorithm: Int {
			
			case none
			case pkcs1
			case md2
			case md5
			case sha1
		
			/// Algorithm specific padding.
			public var padding: SecPadding {
				
				switch self {
					
				case .none:
					return .none
				case .pkcs1:
					return .PKCS1
				case .md2:
					return .PKCS1MD2
				case .md5:
					return .PKCS1MD5
				case .sha1:
					return .PKCS1SHA1
				}
			}
		}
	
	#elseif os(Linux)
	
	
	#endif
}
