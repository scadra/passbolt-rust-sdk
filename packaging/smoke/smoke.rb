# The installed gem loads its native library, maps Rust errors to Ruby exceptions and exposes
# the Ruby names of the generated bindings.
require "passbolt"

begin
  Passbolt.get_key_fingerprint("not a key")
rescue Passbolt::CryptoError => e
  abort "not a Passbolt::Error: #{e.class.ancestors}" unless e.is_a?(Passbolt::Error)
  abort "message: #{e.message}" unless e.message == e.reason
  puts "ok: #{e.inspect}"
else
  abort "expected a crypto error"
end

missing = Passbolt::RECORDS.reject { |name| Passbolt.const_get(name, false) == PassboltFfi.const_get(name) }
abort "not under Passbolt: #{missing}" unless missing.empty?
abort "Passbolt::Client" unless Passbolt::Client < PassboltFfi::PassboltClient
abort "PassboltFfi::AsyncPassboltClient is broken in Ruby" if defined?(PassboltFfi::AsyncPassboltClient)
puts "ok: Passbolt names"

# The generator of the extension, without a session.
abort "password" unless Passbolt.generate_password(length: 24).length == 24
passphrase = Passbolt.generate_passphrase(words: 5, word_separator: "-", word_case: Passbolt::WordCase::UPPERCASE)
abort "passphrase: #{passphrase}" unless passphrase == passphrase.upcase
abort "strength" unless Passbolt.secret_strength(Passbolt.generate_secret) == Passbolt::Strength::STRONG
abort "pin" unless Passbolt.generate_pin_code(6).length == 6
puts "ok: generator"
