# frozen_string_literal: true

# Entry point of the gem: the generated UniFFI bindings (PassboltFfi), with Ruby names.
#
#   require "passbolt"
#
#   Passbolt::Client.login(url, File.read("private.asc"), passphrase) do |client|
#     client.list_resource_views("github").each { |view| puts view["name"] }
#   end
require "ffi"
require "json"

module Passbolt
  # The native library of this platform, shipped under lib/native/<os>-<arch>/: the generated
  # bindings load it (`cdylib_path` in crates/passbolt-ffi/uniffi.toml).
  NATIVE_LIBRARY = File.expand_path(
    "native/#{FFI::Platform::OS}-#{FFI::Platform::ARCH}/#{FFI.map_library_name('passbolt_ffi')}",
    __dir__
  )
end

require_relative "passbolt/passbolt_ffi"

module Passbolt
  # In every error the SDK raises: `rescue Passbolt::Error`. The classes below say what failed;
  # each has a `reason`, and Passbolt::ApiError the HTTP `status`.
  module Error
    def to_s
      respond_to?(:status) ? "#{reason} (HTTP #{status})" : reason.to_s
    end
  end

  PassboltFfi::PassboltFfiError.constants.each do |name|
    PassboltFfi::PassboltFfiError.const_get(name).prepend(Error)
  end

  TransportError = PassboltFfi::PassboltFfiError::Transport
  AuthError = PassboltFfi::PassboltFfiError::Auth
  CryptoError = PassboltFfi::PassboltFfiError::Crypto
  ApiError = PassboltFfi::PassboltFfiError::Api
  NotFoundError = PassboltFfi::PassboltFfiError::NotFound
  ConfigError = PassboltFfi::PassboltFfiError::Config
  InvalidArgumentError = PassboltFfi::PassboltFfiError::InvalidArgument

  # The records without their Ffi prefix: Passbolt::Resource, Passbolt::Folder, Passbolt::User…
  PassboltFfi.constants.grep(/\AFfi./).each do |name|
    const_set(name.to_s.delete_prefix("Ffi"), PassboltFfi.const_get(name))
  end

  # Passbolt's permission types, for share_resource and share_folder.
  module PermissionType
    READ = 1
    UPDATE = 7
    OWNER = 15
    # Removes the access of the users and groups given.
    REVOKE = -1
  end

  # The server public key and its fingerprint, to pin with
  # `Client.login(..., server_public_key:)` once the user confirmed the fingerprint.
  def self.fetch_server_key(server_url, tls_skip_verify: false)
    PassboltFfi.fetch_server_key(server_url, tls_skip_verify)
  end

  def self.get_key_fingerprint(private_key_armored)
    PassboltFfi.get_key_fingerprint(private_key_armored)
  end

  # The ciphertext, armored, for every key of public_keys_armored.
  def self.encrypt_message(plaintext, public_keys_armored)
    PassboltFfi.encrypt_message(plaintext, public_keys_armored)
  end

  # The plaintext, as a binary String.
  def self.decrypt_message(armored_message, private_key_armored, passphrase)
    PassboltFfi.decrypt_message(armored_message, private_key_armored, passphrase)
  end

  # A logged-in session. The calls block; the methods not redefined here are those of
  # PassboltFfi::PassboltClient, with positional arguments.
  class Client < PassboltFfi::PassboltClient
    # Log in with GPGAuth. With a block, yields the client and logs out at the end.
    #
    # server_public_key and metadata_key_fingerprint pin the keys saved earlier;
    # mfa_totp_token is the base32 TOTP secret of an account with TOTP; timeout_seconds is 60
    # by default, 0 waits forever.
    def self.login(server_url, private_key_armored, passphrase, server_public_key: nil,
                   metadata_key_fingerprint: nil, mfa_totp_token: nil, timeout_seconds: nil,
                   tls_skip_verify: false, proxy: nil, client_certificate_pem: nil,
                   client_key_pem: nil)
      options = LoginOptions.new(
        tls_skip_verify: tls_skip_verify, proxy: proxy, mfa_totp_token: mfa_totp_token,
        server_public_key: server_public_key, metadata_key_fingerprint: metadata_key_fingerprint,
        timeout_seconds: timeout_seconds, client_certificate_pem: client_certificate_pem,
        client_key_pem: client_key_pem
      )
      client = login_with_config(server_url, private_key_armored, passphrase, options)
      return client unless block_given?

      begin
        yield client
      ensure
        client.logout
      end
    end

    # A resource with its metadata and secret decrypted, as a Hash: "name", "username",
    # "uris", "description", "password", "metadata", "secret"…
    def get_resource_view(id)
      JSON.parse(super)
    end

    # The resources with their metadata decrypted, searched by name; with their secrets too
    # with with_secrets. One that does not decrypt has an "error".
    def list_resource_views(search = nil, with_secrets: false)
      JSON.parse(super(search, with_secrets))
    end

    # create_resource(name: "GitHub", username: "ada", password: "…"), or with a Hash. The
    # fields: name, username, uris, description, password, totp, note, pin_code,
    # custom_fields, folder_parent_id, expired, resource_type, metadata_fields, secret_fields.
    def create_resource(fields = {}, **more)
      super(JSON.generate(fields.merge(more)))
    end

    # Changes the fields given, keeps the others; expired: nil clears the expiry.
    def update_resource(id, changes = {}, **more)
      super(id, JSON.generate(changes.merge(more)))
    end

    def list_resources(search = nil, favorites_only: false, owned_by_me: false)
      super(search, favorites_only, owned_by_me)
    end

    def list_folders(search = nil)
      super
    end

    def list_users(search = nil, group_id: nil, admin_only: false)
      super(search, group_id, admin_only)
    end

    def share_resource(id, permission_type:, user_ids: [], group_ids: [])
      super(id, user_ids, group_ids, permission_type)
    end

    def share_folder(id, permission_type:, user_ids: [], group_ids: [], with_content: false)
      super(id, user_ids, group_ids, permission_type, with_content)
    end

    def move_resource(id, folder_id = nil)
      super
    end

    def move_folder(id, folder_id = nil)
      super
    end

    def create_folder(name, folder_parent_id: nil)
      super(name, folder_parent_id)
    end

    def update_user(id, first_name: nil, last_name: nil, role: nil)
      super(id, first_name, last_name, role)
    end

    def create_group(name, member_ids: [], manager_ids: [])
      super(name, member_ids, manager_ids)
    end

    def update_group(id, name: nil, add_member_ids: [], add_manager_ids: [], remove_member_ids: [])
      super(id, name, add_member_ids, add_manager_ids, remove_member_ids)
    end

    def create_comment(resource_id, content, parent_id: nil)
      super(resource_id, content, parent_id)
    end
  end
end
