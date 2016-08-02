//
//  XCTestManifests.swift
//  Cryptor
//
//  Created by Bill Abt on 8/1/16.
//
//

import XCTest

#if !os(macOS)
	public func allTests() -> [XCTestCaseEntry] {
		return [
			testCase(CryptorTests.allTests),
		]
	}
#endif
