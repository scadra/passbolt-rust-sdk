# Passbolt SDK for Ruby: the UniFFI bindings and the native library of each platform.
Gem::Specification.new do |spec|
  spec.name = "switch-case-passbolt-sdk"
  spec.version = ENV.fetch("SDK_VERSION", "0.0.0")
  spec.summary = "Passbolt SDK — Ruby bindings of the Rust SDK"
  spec.license = "AGPL-3.0-or-later"
  spec.authors = ["Passbolt SA"]
  spec.homepage = "https://github.com/scadra/passbolt-rust-sdk"
  spec.required_ruby_version = ">= 3.0"
  spec.files = Dir["lib/**/*"]
  spec.require_paths = ["lib"]
  spec.add_dependency "ffi", "~> 1.15"
end
