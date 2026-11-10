// The objects the session takes and returns, as the SDK serializes them: the Passbolt API field
// names, `null` for an absent value, dates as RFC 3339 strings. The options of the methods
// (filters, shares, users and groups to create or change) are camelCase, as `LoginOptions`.

/** A date and time, RFC 3339 (`2024-01-01T10:00:00Z`). */
export type Timestamp = string;

/** A JSON value, as the server or the encrypted data hold it. */
export type Json = null | boolean | number | string | Json[] | { [key: string]: Json };

/**
 * What the SDK passes to `LoginOptions.fetch`: plain values, which any `fetch` takes (the global
 * one, undici's, node-fetch).
 */
export interface FetchInit {
  method: string;
  headers: Record<string, string>;
  body?: ArrayBuffer;
  credentials: "include";
  mode: "cors";
}

/** What the SDK reads of the response of `LoginOptions.fetch`: a `Response` has it. */
export interface FetchResponse {
  readonly status: number;
  readonly headers: Iterable<[string, string]> & { getSetCookie?(): string[] };
  arrayBuffer(): Promise<ArrayBuffer>;
}

/** Sends a request of the SDK, as `fetch(url, init)` does. */
export type FetchFunction = (url: string, init: FetchInit) => Promise<FetchResponse>;

/** Options of `PassboltSession.fetchServerKey`. */
export interface FetchServerKeyOptions {
  /** Sends the request instead of the global `fetch`: see `LoginOptions.fetch`. */
  fetch?: FetchFunction;
}

/** Options of `PassboltSession.login`. */
export interface LoginOptions {
  /** Returns the `csrfToken` cookie, or a promise of it; e.g. with `browser.cookies.get`. */
  csrfTokenProvider?: () => string | null | undefined | Promise<string | null | undefined>;
  /**
   * Sends the requests instead of the global `fetch`: with a proxy, or a TLS setting the global
   * `fetch` of Node cannot take, e.g. undici's `fetch` with a `dispatcher`.
   */
  fetch?: FetchFunction;
  /** The TOTP code answering the MFA challenge. */
  totpCode?: string;
  /** The armored server key pinned with `PassboltSession.fetchServerKey`. */
  serverPublicKey?: string;
  /** The shared metadata key fingerprint pinned with `metadataKeyFingerprint()`. */
  metadataKeyFingerprint?: string;
  /** The OpenPGP.js module (`import * as openpgp from "openpgp"`) messages are read and written with. Default: rpgp. */
  openpgp?: object;
}

/** What every rejected promise and thrown error of the SDK carries in `code`. */
export type PassboltErrorCode =
  | "NETWORK"
  | "TIMEOUT"
  | "LOGIN_FAILED"
  | "MFA_REQUIRED"
  | "MFA_FAILED"
  | "MFA_UNSUPPORTED"
  | "MFA_LOCKED_OUT"
  | "SESSION_EXPIRED"
  | "SERVER_IDENTITY_MISMATCH"
  | "INVALID_KEY"
  | "DECRYPTION_FAILED"
  | "ENCRYPTION_FAILED"
  | "UNTRUSTED_METADATA_KEY"
  | "CRYPTO"
  | "NOT_FOUND"
  | "API"
  | "INVALID_RESPONSE"
  | "CONFIG"
  | "INVALID_ARGUMENT"
  | "UNKNOWN";

/**
 * The errors the SDK throws: an `Error` named `PassboltError`; `isPassboltError` tells them
 * apart from others.
 */
export interface PassboltError extends Error {
  name: "PassboltError";
  code: PassboltErrorCode;
  /** The HTTP status of an API error. */
  status?: number;
  /** The fields the server refused, by field name, for an API error. */
  validationErrors?: Json;
}

export interface ServerKey {
  /** Computed from the key, to show to the user. */
  fingerprint: string;
  armoredKey: string;
}

/** 1 read, 7 update, 15 owner. */
export type PermissionType = 1 | 7 | 15;

/** `listResources`: every field is optional. */
export interface ResourceFilter {
  /** Part of the name. */
  search?: string;
  favoritesOnly?: boolean;
  ownedByMe?: boolean;
}

/** `listResourceViews`: every field is optional. */
export interface ResourceViewFilter {
  /** Part of the decrypted name. */
  search?: string;
  /** Decrypt the secrets too. */
  withSecrets?: boolean;
}

/** `listFolders`. */
export interface FolderFilter {
  /** Part of the name. */
  search?: string;
}

/** `listUsers`: every field is optional. */
export interface UserFilter {
  search?: string;
  /** Members of this group only. */
  groupId?: string;
  adminOnly?: boolean;
}

/** `shareResource`: the users and groups to give `permissionType` to, or to revoke with -1. */
export interface Share {
  userIds?: string[];
  groupIds?: string[];
  permissionType: PermissionType | -1;
}

/** `shareFolder`. */
export interface FolderShare extends Share {
  /** Share the sub-folders and the resources the user owns in it too. */
  withContent?: boolean;
}

/** `createUser`. */
export interface NewUser {
  /** The email address. */
  username: string;
  firstName: string;
  lastName: string;
  /** `user` (default) or `admin`. */
  role?: "user" | "admin";
}

/** `updateUser`: only the fields to change. */
export interface UserChanges {
  firstName?: string;
  lastName?: string;
  role?: "user" | "admin";
}

/** `createGroup`: a manager is also a member. */
export interface NewGroup {
  name: string;
  memberIds?: string[];
  managerIds?: string[];
}

/** `updateGroup`: only the changes. */
export interface GroupChanges {
  name?: string;
  addMemberIds?: string[];
  addManagerIds?: string[];
  removeMemberIds?: string[];
}

export interface Permission {
  id: string | null;
  /** `Resource` or `Folder`. */
  aco: string | null;
  aco_foreign_key: string | null;
  /** `User` or `Group`. */
  aro: string | null;
  aro_foreign_key: string | null;
  type: number | null;
  created: Timestamp | null;
  modified: Timestamp | null;
  user: User | null;
  group: Group | null;
}

export interface Favorite {
  id: string | null;
  foreign_model: string | null;
  foreign_key: string | null;
  created: Timestamp | null;
}

export interface Secret {
  id: string | null;
  resource_id: string | null;
  user_id: string | null;
  /** The armored OpenPGP message. */
  data: string | null;
  created: Timestamp | null;
  modified: Timestamp | null;
}

export interface Tag {
  id: string;
  slug: string;
  is_shared: boolean | null;
  created: Timestamp | null;
  modified: Timestamp | null;
}

/** A resource as the API sends it: v5 names, usernames and URIs are in the encrypted `metadata`. */
export interface Resource {
  id: string;
  /** Empty for a v5 resource. */
  name: string;
  username: string | null;
  uri: string | null;
  description: string | null;
  folder_parent_id: string | null;
  resource_type_id: string | null;
  created: Timestamp | null;
  modified: Timestamp | null;
  created_by: string | null;
  modified_by: string | null;
  personal: boolean | null;
  favorite: Favorite | null;
  secrets: Secret[];
  permission: Permission | null;
  permissions: Permission[];
  tags: Tag[];
  /** v5: the armored encrypted metadata. */
  metadata: Json;
  metadata_key_id: string | null;
  /** `user_key` or `shared_key`. */
  metadata_key_type: string | null;
  expired: Timestamp | null;
  deleted?: boolean | null;
}

/** A resource with its metadata decrypted, and its secret when asked for. */
export interface ResourceView {
  id: string;
  name: string;
  username: string;
  /** The first of `uris`. */
  uri: string;
  uris: string[];
  description: string;
  folder_parent_id: string | null;
  /** The type slug: `v5-default`, `password-and-description`… */
  resource_type: string | null;
  resource_type_id: string | null;
  personal: boolean | null;
  metadata_key_type: string | null;
  created: Timestamp | null;
  modified: Timestamp | null;
  expired: Timestamp | null;
  /** The decrypted v5 metadata, or the v4 fields. */
  metadata: { [field: string]: Json };
  password?: string | null;
  /** The decrypted secret. */
  secret?: { [field: string]: Json } | null;
  /** Why the metadata or the secret could not be decrypted. */
  error?: string | null;
}

export interface TotpData {
  /** Base32. */
  secret_key?: string;
  /** `SHA1`, `SHA256` or `SHA512`. */
  algorithm?: string;
  digits?: number;
  period?: number;
}

/** What `decryptResourceSecret` returns. */
export interface SecretData {
  password: string | null;
  description: string | null;
  totp: TotpData | null;
}

/** One side of a custom field: `metadata_*` in the metadata, `secret_*` in the secret. */
export interface CustomField {
  id: string;
  /** `text`, `password`, `boolean`, `number` or `uri`. */
  type: string;
  metadata_key?: string;
  metadata_value?: Json;
  secret_key?: string;
  secret_value?: Json;
}

/** `createResource`: the fields of the resource; the type follows them when not given. */
export interface NewResource {
  /** Type slug; by default from the fields set and the server's default version. */
  resource_type?: string | null;
  name?: string;
  username?: string | null;
  uris?: string[];
  description?: string | null;
  /** Secret note, the content of a `v5-note`. */
  note?: string | null;
  password?: string | null;
  totp?: TotpData | null;
  pin_code?: string | null;
  icon?: Json;
  custom_fields?: CustomField[];
  folder_parent_id?: string | null;
  /** Expiry, RFC 3339. */
  expired?: string | null;
  metadata_fields?: { [field: string]: Json };
  secret_fields?: { [field: string]: Json };
  /** Leave the permissions of the parent folder out. */
  without_folder_permissions?: boolean;
}

/** `updateResource`: only the fields to change; `expired: null` clears the expiry. */
export interface ResourceChanges {
  name?: string | null;
  username?: string | null;
  uris?: string[] | null;
  description?: string | null;
  note?: string | null;
  password?: string | null;
  pin_code?: string | null;
  totp?: TotpData | null;
  remove_totp?: boolean;
  expired?: string | null;
  metadata_fields?: { [field: string]: Json };
  secret_fields?: { [field: string]: Json };
}

export interface Folder {
  id: string;
  name: string;
  folder_parent_id: string | null;
  created: Timestamp | null;
  modified: Timestamp | null;
  created_by: string | null;
  modified_by: string | null;
  personal: boolean | null;
  permission: Permission | null;
  permissions: Permission[];
}

export interface FolderTreeNode {
  folder: Folder;
  children: FolderTreeNode[];
}

export interface UserProfile {
  first_name: string | null;
  last_name: string | null;
  avatar: Json;
}

export interface Role {
  id: string | null;
  /** `user` or `admin`. */
  name: string | null;
}

export interface GpgKey {
  id: string | null;
  user_id: string | null;
  armored_key: string | null;
  bits: number | null;
  fingerprint: string | null;
  key_created: Timestamp | null;
}

export interface GroupUser {
  id: string | null;
  group_id: string | null;
  user_id: string | null;
  /** A manager of the group. */
  is_admin: boolean | null;
  created: Timestamp | null;
  user: User | null;
}

export interface User {
  id: string;
  username: string | null;
  role_id: string | null;
  created: Timestamp | null;
  modified: Timestamp | null;
  active: boolean | null;
  deleted: boolean | null;
  /** When the account was disabled. */
  disabled?: string | null;
  profile: UserProfile | null;
  role: Role | null;
  gpg_key: GpgKey | null;
  groups_users: GroupUser[];
}

export interface Group {
  id: string;
  name: string;
  created: Timestamp | null;
  modified: Timestamp | null;
  created_by: string | null;
  modified_by: string | null;
  deleted: boolean | null;
  groups_users: GroupUser[];
  my_group_user: GroupUser | null;
}

export interface UserDeleteDryRun {
  resources_sole_owner_count: number;
  folders_sole_owner_count: number;
  groups_sole_manager_count: number;
}

export interface GroupDeleteDryRun {
  resources_sole_group_count: number;
  folders_sole_group_count: number;
}

/** A shared resource or folder only the deleted user or group owns. */
export interface OwnedItem {
  id: string;
  permissions: Permission[];
}

/** A group with other members only the deleted user manages. */
export interface ManagedGroup {
  id: string;
  name: string;
  groups_users: GroupUser[];
}

/** What blocks a deletion: each item needs a new owner, each group a new manager. */
export interface DeleteBlockers {
  resources: OwnedItem[];
  folders: OwnedItem[];
  groups: ManagedGroup[];
  /** Groups the deleted user is the only member of: deleted with them. */
  groups_to_delete: string[];
}

export interface Comment {
  id: string;
  parent_id: string | null;
  foreign_key: string | null;
  foreign_model: string | null;
  content: string;
  created: Timestamp | null;
  modified: Timestamp | null;
  created_by: string | null;
  modified_by: string | null;
  creator: User | null;
}

/** A user or a group to share with. */
export interface Aro {
  id: string;
  /** `User` or `Group`. */
  type: string | null;
  username: string | null;
  profile: UserProfile | null;
  name: string | null;
}

export interface PasswordExpirySettings {
  id?: string | null;
  /** Days. */
  default_expiry_period?: number | null;
  policy_override?: boolean | null;
  automatic_expiry?: boolean | null;
  automatic_update?: boolean | null;
}

/** How passwords are generated: 18 characters of every set but emoji by default. */
export interface PasswordGeneratorSettings {
  length: number;
  /** Bounds of `length`, 8 and 128 by default. */
  min_length: number;
  max_length: number;
  /** `A-Z` */
  mask_upper: boolean;
  /** `a-z` */
  mask_lower: boolean;
  /** `0-9` */
  mask_digit: boolean;
  /** `{ [ ( | ) ] }` */
  mask_parenthesis: boolean;
  /** The emoticons of Unicode 6. */
  mask_emoji: boolean;
  /** `# $ % & @ ^ ~` */
  mask_char1: boolean;
  /** `. , : ;` */
  mask_char2: boolean;
  /** `'`, `"` and the backtick. */
  mask_char3: boolean;
  /** `/ \ _ -` */
  mask_char4: boolean;
  /** `< * + ! ? =` */
  mask_char5: boolean;
  /** Leaves out `O l | I 0 1`. */
  exclude_look_alike_chars: boolean;
}

export type WordCase = "lowercase" | "uppercase" | "camelcase";

/** How passphrases are generated: 9 lowercase words joined by spaces by default. */
export interface PassphraseGeneratorSettings {
  words: number;
  word_separator: string;
  word_case: WordCase;
  /** Bounds of `words`, 4 and 40 by default. */
  min_words: number;
  max_words: number;
}

/** The password policies of the organization, the `PasswordPoliciesDto` of the extension. */
export interface PasswordPolicies {
  default_generator: "password" | "passphrase";
  /** Check new passwords against Have I Been Pwned. */
  external_dictionary_check: boolean;
  password_generator_settings: PasswordGeneratorSettings;
  passphrase_generator_settings: PassphraseGeneratorSettings;
  /** Where the server read them: `default`, `file`, `env`, `db`… */
  source?: string;
  id?: string;
  created?: string;
  created_by?: string;
  modified?: string;
  modified_by?: string;
}

/** The strength the extension shows: its ids. */
export type Strength = "not_available" | "very-weak" | "weak" | "fair" | "strong" | "very-strong";

export interface ResourceType {
  id: string;
  slug: string;
  name: string | null;
  /** The JSON Schemas of the `resource` and of the `secret`. */
  definition: Json;
}

export interface MetadataTypesSettings {
  /** `v4` or `v5`. */
  default_resource_types?: string | null;
  default_folder_type?: string | null;
  default_tag_type?: string | null;
  default_comment_type?: string | null;
  allow_creation_of_v5_resources?: boolean | null;
  allow_creation_of_v5_folders?: boolean | null;
  allow_creation_of_v5_tags?: boolean | null;
  allow_creation_of_v5_comments?: boolean | null;
  allow_creation_of_v4_resources?: boolean | null;
  allow_creation_of_v4_folders?: boolean | null;
  allow_creation_of_v4_tags?: boolean | null;
  allow_creation_of_v4_comments?: boolean | null;
}

export interface MetadataKeysSettings {
  allow_usage_of_personal_keys?: boolean | null;
  zero_knowledge_key_share?: boolean | null;
}
