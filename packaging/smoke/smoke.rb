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
