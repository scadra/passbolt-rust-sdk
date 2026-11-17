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

# The OpenPGP engine of the native library encrypts and decrypts in this host: a test key of the
# repository, CI checking the engine each package is built with.
engine = Passbolt.openpgp_engine
expected = ENV["PASSBOLT_EXPECTED_ENGINE"]
abort "engine #{engine}, expected #{expected}" if expected && engine != expected
keys = ENV.fetch("PASSBOLT_SMOKE_KEYS", "crates/passbolt-sdk/tests/fixtures/keys")
armored = Passbolt.encrypt_message("smoke".b, [File.read(File.join(keys, "erin_public.asc"))])
plaintext = Passbolt.decrypt_message(armored, File.read(File.join(keys, "erin_private.asc")), "erin-passphrase")
abort "the message did not come back" unless plaintext == "smoke".b
puts "ok: #{engine} encrypts and decrypts"
