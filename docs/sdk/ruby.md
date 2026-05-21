---
title: Ruby
sidebar_position: 9
---

# Ruby

```bash
gem install switch-case-passbolt-sdk
```

Ruby 3.0 or later, with the `ffi` gem; the gem holds the native library of Linux (x86_64,
aarch64), macOS and Windows.

## Log in and list

```ruby
require "json"
require "passbolt_sdk"

client = PassboltFfi::PassboltClient.login(
  "https://passbolt.example.com", File.read("private.asc"), ENV.fetch("PASSBOLT_PASSPHRASE")
)
begin
  JSON.parse(client.list_resource_views("github", false)).each do |view|
    puts "#{view["id"]} #{view["name"]}"
  end
ensure
  client.logout
end
```

## Errors

```ruby
begin
  PassboltFfi.get_key_fingerprint("not a key")
rescue PassboltFfi::PassboltFfiError::Crypto => error
  puts "not a key: #{error.message}"
end
```

`PassboltFfi::PassboltClient.login_with_config` takes a `PassboltFfi::FfiLoginOptions.new(...)`,
with the keyword arguments of the [Python](python.md#pinning-the-server-mfa-tls) example. The
calls block. The methods are those of the [overview](README.md#what-the-api-covers), in
snake_case.
