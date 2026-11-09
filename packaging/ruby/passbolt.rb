# frozen_string_literal: true

# Entry point of the gem: the generated UniFFI bindings (PassboltFfi), with Ruby names.
#
#   require "passbolt"
#
#   Passbolt::Client.login(url, File.read("private.asc"), passphrase) do |client|
#     client.list_resource_views("github").each { |view| puts view.name }
#   end
require "English"
require "ffi"

module Passbolt
  # The native library of this platform, shipped under lib/native/<os>-<arch>/: the generated
  # bindings load it (`cdylib_path` in crates/passbolt-ffi/uniffi.toml).
  NATIVE_LIBRARY = File.expand_path(
    "native/#{FFI::Platform::OS}-#{FFI::Platform::ARCH}/#{FFI.map_library_name('passbolt_ffi')}",
    __dir__
  )
end

require_relative "passbolt/passbolt_ffi"

# The Ruby generator of UniFFI 0.29 does not support async methods: each call of the generated
# AsyncPassboltClient would return the handle of a Rust future, and leak it. Ruby has the
# blocking Passbolt::Client only.
PassboltFfi.send(:remove_const, :AsyncPassboltClient)

module Passbolt
  # In every error the SDK raises: `rescue Passbolt::Error`. The classes below say what failed;
  # each has a `reason`, and Passbolt::ApiError the HTTP `status`.
  module Error
    def to_s
      respond_to?(:status) ? "#{reason} (HTTP #{status})" : reason.to_s
    end
  end

  PassboltFfi::PassboltError.constants.each do |name|
    PassboltFfi::PassboltError.const_get(name).prepend(Error)
  end

  TransportError = PassboltFfi::PassboltError::Transport
  AuthError = PassboltFfi::PassboltError::Auth
  CryptoError = PassboltFfi::PassboltError::Crypto
  ApiError = PassboltFfi::PassboltError::Api
  NotFoundError = PassboltFfi::PassboltError::NotFound
  ConfigError = PassboltFfi::PassboltError::Config
  InvalidArgumentError = PassboltFfi::PassboltError::InvalidArgument

  # The records, under Passbolt: Passbolt::ResourceView, Passbolt::NewResource, Passbolt::Folder…
  RECORDS = %i[
    Aro Comment DeleteBlockers Favorite Folder FolderQuery FolderTreeNode GpgKey Group
    GroupDeleteDryRun GroupUser LoginOptions ManagedGroup MetadataKeysSettings
    MetadataTypesSettings NewResource OwnedItem PasswordExpirySettings Permission Resource
    ResourceChanges ResourceQuery ResourceType ResourceView Role Secret SecretData ServerKey Tag
    TotpData User UserDeleteDryRun UserProfile UserQuery
  ].freeze
  RECORDS.each { |name| const_set(name, PassboltFfi.const_get(name)) }

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
  # PassboltFfi::PassboltClient.
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
        in_flight = $ERROR_INFO
        begin
          client.logout
        rescue Passbolt::Error
          # A failed logout raises, unless it would hide the exception that left the block.
          raise unless in_flight
        end
      end
    end

    # The flags and optional arguments below are keywords; the generated methods take them as
    # positional arguments with defaults.

    def list_resource_views(search = nil, with_secrets: false)
      super(search, with_secrets)
    end

    def list_resources(search = nil, favorites_only: false, owned_by_me: false)
      super(search, favorites_only, owned_by_me)
    end

    def list_users(search = nil, group_id: nil, admin_only: false)
      super(search, group_id, admin_only)
    end

    def share_resource(id, permission_type:, user_ids: [], group_ids: [])
      super(id, permission_type, user_ids, group_ids)
    end

    def share_folder(id, permission_type:, user_ids: [], group_ids: [], with_content: false)
      super(id, permission_type, user_ids, group_ids, with_content)
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
