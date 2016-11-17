//
//  Package.swift
//  Cryptor
//
//  Copyright © 2016 IBM. All rights reserved.
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

import PackageDescription

#if os(macOS) || os(iOS) || os(tvOS) || os(watchOS)
	let url = "https://github.com/IBM-Swift/CommonCrypto.git"
	let majorVersion = 0
	let minorVersion = 1
#elseif os(Linux)
	let url = "https://github.com/IBM-Swift/COpenSSL.git"
	let majorVersion = 0
	let minorVersion = 3
#else
	fatalError("Unsupported OS")
#endif

let package = Package(
	name: "Cryptor",
	targets: [Target(name: "Cryptor")],
	dependencies: [
		.Package(url: url, majorVersion: majorVersion, minor: minorVersion),
	],
	exclude: ["Cryptor.xcodeproj", "README.md", "Sources/Info.plist"]
)
