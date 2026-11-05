---
title: Ruby
sidebar_position: 9
---

# Ruby

```bash
gem install switch-case-passbolt-sdk
```

Ruby 3.0 or later, with the `ffi` gem; the gem holds the native library of Linux (x86_64,
aarch64), macOS and Windows. Its calls block.

## Log in and list

```ruby
require "passbolt"

Passbolt::Client.login(
  "https://passbolt.example.com", File.read("private.asc"), ENV.fetch("PASSBOLT_PASSPHRASE")
) do |client|
  client.list_resource_views("github").each do |view|
    puts "#{view["id"]} #{view["name"]}"
  end
end
```

With a block, `login` logs out at the end; without one it returns the client: call
`client.logout` when done.

## Pinning the server, MFA, TLS

```ruby
server_key = Passbolt.fetch_server_key("https://passbolt.example.com")
puts "Check this fingerprint with your administrator: #{server_key.fingerprint}"

client = Passbolt::Client.login(
  "https://passbolt.example.com", private_key, passphrase,
  server_public_key: server_key.armored_key,
  mfa_totp_token: nil,          # the base32 TOTP secret, for an account with TOTP
  metadata_key_fingerprint: nil,
  timeout_seconds: nil,         # 60 by default, 0 waits forever
  tls_skip_verify: false,
  proxy: nil,
  client_certificate_pem: nil   # and client_key_pem:, for mTLS
)
```

Every keyword is optional.

## Reading and writing

```ruby
view = client.get_resource_view(resource_id)
puts view["password"]

created = client.create_resource(name: "GitHub", username: "ada", password: "…")
client.update_resource(created.id, password: "new")
client.share_resource(created.id, user_ids: [user_id], permission_type: Passbolt::PermissionType::UPDATE)

folder = client.create_folder("Ops")
client.move_resource(created.id, folder.id)
```

Resource views are Hashes parsed from the server's JSON; the other calls return objects with
readers: `Passbolt::Resource`, `Passbolt::Folder`, `Passbolt::User`…

## Errors

```ruby
begin
  Passbolt.get_key_fingerprint("not a key")
rescue Passbolt::CryptoError => e
  puts "not a key: #{e.message}"
rescue Passbolt::ApiError => e
  puts "the server answered #{e.status}: #{e.reason}"
rescue Passbolt::Error => e
  puts "failed: #{e.message}"
end
```

Every error of the SDK is a `Passbolt::Error`: `TransportError`, `AuthError`, `CryptoError`,
`ApiError`, `NotFoundError`, `ConfigError` or `InvalidArgumentError`.

The methods are those of the [overview](README.md#what-the-api-covers), in snake_case. Flags and
optional arguments are keywords (`list_resources(search = nil, favorites_only: false,
owned_by_me: false)`, `list_users(group_id:, admin_only:)`, `share_folder(id, permission_type:,
user_ids:, group_ids:, with_content:)`); the others are positional. The generated bindings stay
available as `PassboltFfi`.
