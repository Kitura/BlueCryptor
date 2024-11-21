Pod::Spec.new do |s|
s.name        = "BlueCryptor"
s.version     = "2.0.2"
s.summary     = "Swift cross-platform crypto library using CommonCrypto/libcrypto via Package Manager."
s.homepage    = "https://github.com/Kitura/BlueCryptor"
s.license     = { :type => "Apache License, Version 2.0" }
s.author     = "IBM & Kitura Project Authors"
s.module_name  = 'Cryptor'

s.requires_arc = true
s.swift_version = '5.2'
s.osx.deployment_target = "11.5"
s.ios.deployment_target = "14.5"
s.tvos.deployment_target = "14.5"
s.watchos.deployment_target = "7.5"
s.source   = { :git => "https://github.com/Kitura/BlueCryptor.git", :tag => s.version }
s.source_files = "Sources/Cryptor/*.swift"
s.pod_target_xcconfig =  {
'SWIFT_VERSION' => '5.0',
}
end
