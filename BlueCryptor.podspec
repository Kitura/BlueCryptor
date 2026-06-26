Pod::Spec.new do |s|

  s.name              = "BlueCryptor"
  s.module_name       = 'Cryptor'
  s.version           = "2.0.3"
  s.cocoapods_version = '~> 1.16'
  s.summary           = "Swift cross-platform crypto library using CommonCrypto/libcrypto via Package Manager."
  s.homepage          = "https://github.com/Kitura/BlueCryptor"
  s.license           = {
                          :type => "Apache License, Version 2.0"
                        }
  s.author            = "IBM & Kitura Project Authors"
  s.source            = {
                          :git => "https://github.com/Kitura/BlueCryptor.git",
                          :tag => s.version
                        }

  s.swift_version = '5.8'
  
  s.ios.deployment_target = "12.0"
  s.osx.deployment_target = "11.0"
  s.tvos.deployment_target = "12.0"
  s.watchos.deployment_target = "8.0"
  
  s.source_files = "Sources/Cryptor/*.swift"

end
