Pod::Spec.new do |s|
s.name        = "BlueCryptor"
s.version     = "1.0.26"
s.summary     = "Swift cross-platform crypto library using CommonCrypto/libcrypto via Package Manager."
s.homepage    = "https://github.com/IBM-Swift/BlueCryptor"
s.license     = { :type => "Apache License, Version 2.0" }
s.author     = "IBM"
s.module_name  = 'Cryptor'

s.requires_arc = true
s.osx.deployment_target = "10.11"
s.ios.deployment_target = "10.0"
s.tvos.deployment_target = "10.0"
s.watchos.deployment_target = "2.0"
s.source   = { :git => "https://github.com/IBM-Swift/BlueCryptor.git", :tag => s.version }
s.source_files = "Sources/Cryptor/*.swift"
s.pod_target_xcconfig =  {
'SWIFT_VERSION' => '4.2',
}
end
