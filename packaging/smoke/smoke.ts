// Compiled with `tsc --strict --noEmit` against the installed package: the declarations hold
// the types of the objects the session takes and returns. Never run.
import {
  PassboltSession,
  generatePassphrase,
  generatePassword,
  generatePinCode,
  generateSecret,
  isPassboltError,
  secretEntropy,
  secretStrength,
} from "@switch-case/passbolt-sdk";
import type {
  DeleteBlockers,
  Folder,
  FolderTreeNode,
  Group,
  LoginOptions,
  NewResource,
  PassboltErrorCode,
  PasswordPolicies,
  Resource,
  ResourceChanges,
  ResourceView,
  User,
} from "@switch-case/passbolt-sdk";

export async function typedSession(serverUrl: string, privateKey: string, passphrase: string) {
  const options: LoginOptions = { csrfTokenProvider: async () => "token", totpCode: "123456" };
  const session: PassboltSession = await PassboltSession.login(serverUrl, privateKey, passphrase, options);
  await PassboltSession.login(serverUrl, privateKey, passphrase);

  const views: ResourceView[] = await session.listResourceViews({ search: "github", withSecrets: true });
  await session.listResourceViews();
  const names: string[] = views.map((view) => view.name);
  const password: string | null | undefined = views[0]?.password;
  await session.listResources({ favoritesOnly: true });

  const newResource: NewResource = { name: "GitHub", username: "ada", uris: ["https://github.com"] };
  const created: Resource = await session.createResource(newResource);
  const changes: ResourceChanges = { password: "new", expired: null };
  await session.updateResource(created.id, changes);

  const folder: Folder = await session.createFolder("Ops");
  await session.shareResource(created.id, { userIds: [session.userId], permissionType: 7 });
  await session.shareFolder(folder.id, { groupIds: [], permissionType: -1, withContent: true });
  const tree: FolderTreeNode[] = await session.getFolderTree();
  const me: User = await session.getMe();
  const betty: User = await session.createUser({ username: "betty@passbolt.test", firstName: "Betty", lastName: "Test" });
  await session.updateUser(betty.id, { role: "admin" });
  const group: Group = await session.createGroup({ name: "Ops", managerIds: [me.id] });
  await session.updateGroup(group.id, { addMemberIds: [betty.id] });
  const blockers: DeleteBlockers = await session.userDeleteBlockers(me.id);
  const breaches: number = await session.checkPasswordPwned("hunter2");

  const policies: PasswordPolicies = await session.getPasswordPolicies();
  const secret: string = generateSecret(policies);
  generatePassword({ length: 24, mask_emoji: true });
  generatePassword();
  generatePassphrase({ words: 6, word_case: "camelcase" });
  const pin: string = generatePinCode(6);
  const bits: number = secretEntropy(secret);
  const strong: boolean = secretStrength(secret) === "very-strong";

  let code: PassboltErrorCode | undefined;
  try {
    await session.getResource("missing");
  } catch (error) {
    if (isPassboltError(error)) code = error.code;
  }
  session.free();
  return { names, password, tree, breaches, code, blockers: blockers.groups_to_delete, pin, bits, strong };
}
