package passbolt

// The calls with optional arguments take an option struct: its zero value asks for the
// defaults, a field left out keeps its default, and an empty string is no value. The List
// methods take a pointer, nil for no filter.

// ResourceListOptions filters ListResources.
type ResourceListOptions struct {
	// Search keeps the resources matching a search term; empty for every resource.
	Search string
	// FavoritesOnly keeps the resources marked as favorite.
	FavoritesOnly bool
	// OwnedByMe keeps the resources the user owns.
	OwnedByMe bool
}

// ResourceViewListOptions filters ListResourceViews.
type ResourceViewListOptions struct {
	// Search keeps the resources matching a search term; empty for every resource.
	Search string
	// WithSecrets also decrypts each secret: Password, Totp and SecretJSON are then set.
	WithSecrets bool
}

// FolderListOptions filters ListFolders.
type FolderListOptions struct {
	// Search keeps the folders matching a search term; empty for every folder.
	Search string
}

// UserListOptions filters ListUsers.
type UserListOptions struct {
	// Search keeps the users matching a search term; empty for every user.
	Search string
	// GroupID keeps the members of that group; empty for every group.
	GroupID string
	// AdminOnly keeps the administrators.
	AdminOnly bool
}

// GroupChanges are the changes UpdateGroup makes; the fields left out change nothing.
type GroupChanges struct {
	// Name is the new name; empty keeps it.
	Name string
	// AddMemberIDs are the users added as members.
	AddMemberIDs []string
	// AddManagerIDs are the users added as group managers.
	AddManagerIDs []string
	// RemoveMemberIDs are the users removed from the group, before the others are added.
	RemoveMemberIDs []string
}

// UserChanges are the changes UpdateUser makes; an empty field keeps its value.
type UserChanges struct {
	FirstName string
	LastName  string
	// Role is the role name: "user" or "admin".
	Role string
}

// The permission types of Share and FolderShare, also those of Permission.PermissionType.
const (
	PermissionRead   = 1
	PermissionUpdate = 7
	PermissionOwner  = 15
	// PermissionRevoke removes the permission of the users and groups given.
	PermissionRevoke = -1
)

// Share is what ShareResource grants: one permission type, to users and groups.
type Share struct {
	// Permission is PermissionRead, PermissionUpdate, PermissionOwner or PermissionRevoke.
	Permission int32
	UserIDs    []string
	GroupIDs   []string
}

// FolderShare is what ShareFolder grants: a Share, and whether the content follows.
type FolderShare struct {
	// Permission is PermissionRead, PermissionUpdate, PermissionOwner or PermissionRevoke.
	Permission int32
	UserIDs    []string
	GroupIDs   []string
	// WithContent also shares the sub-folders and resources of the folder the user owns.
	WithContent bool
}

// ListResources lists the resources the user can read, without decrypting them; nil lists
// them all.
func (client *PassboltClient) ListResources(opts *ResourceListOptions) ([]Resource, error) {
	if opts == nil {
		opts = &ResourceListOptions{}
	}
	return client.listResources(optional(opts.Search), opts.FavoritesOnly, opts.OwnedByMe)
}

// ListResourceViews lists the resources the user can read, with their metadata decrypted;
// nil lists them all, without their secrets.
func (client *PassboltClient) ListResourceViews(opts *ResourceViewListOptions) ([]ResourceView, error) {
	if opts == nil {
		opts = &ResourceViewListOptions{}
	}
	return client.listResourceViews(optional(opts.Search), opts.WithSecrets)
}

// ListFolders lists the folders the user can read; nil lists them all.
func (client *PassboltClient) ListFolders(opts *FolderListOptions) ([]Folder, error) {
	if opts == nil {
		opts = &FolderListOptions{}
	}
	return client.listFolders(optional(opts.Search))
}

// ListUsers lists the users; nil lists them all.
func (client *PassboltClient) ListUsers(opts *UserListOptions) ([]User, error) {
	if opts == nil {
		opts = &UserListOptions{}
	}
	return client.listUsers(optional(opts.Search), optional(opts.GroupID), opts.AdminOnly)
}

// UpdateGroup renames a group and changes its members, and returns the group updated.
func (client *PassboltClient) UpdateGroup(id string, changes GroupChanges) (Group, error) {
	return client.updateGroup(id, optional(changes.Name),
		changes.AddMemberIDs, changes.AddManagerIDs, changes.RemoveMemberIDs)
}

// UpdateUser changes the names or the role of a user, and returns the user updated.
func (client *PassboltClient) UpdateUser(id string, changes UserChanges) (User, error) {
	return client.updateUser(id,
		optional(changes.FirstName), optional(changes.LastName), optional(changes.Role))
}

// ShareResource grants, changes or revokes the permission of users and groups on a resource,
// and encrypts its secret for the users who gain access.
func (client *PassboltClient) ShareResource(id string, share Share) error {
	return client.shareResource(id, share.Permission, share.UserIDs, share.GroupIDs)
}

// ShareFolder grants, changes or revokes the permission of users and groups on a folder, and
// on its content with WithContent.
func (client *PassboltClient) ShareFolder(id string, share FolderShare) error {
	return client.shareFolder(id, share.Permission, share.UserIDs, share.GroupIDs, share.WithContent)
}

// optional is nil for an empty string, the "no value" of the option structs.
func optional(s string) *string {
	if s == "" {
		return nil
	}
	return &s
}
