// Compiled with `tsc --strict --noEmit` against the installed package: the declarations hold
// the types of the objects the session takes and returns. Never run.
import { PassboltSession } from "@switch-case/passbolt-sdk";
import type {
  DeleteBlockers,
  Folder,
  FolderTreeNode,
  LoginOptions,
  NewResource,
  Resource,
  ResourceChanges,
  ResourceView,
  User,
} from "@switch-case/passbolt-sdk";

export async function typedSession(serverUrl: string, privateKey: string, passphrase: string) {
  const options: LoginOptions = { csrfTokenProvider: async () => "token", totpCode: "123456" };
  const session: PassboltSession = await PassboltSession.login(serverUrl, privateKey, passphrase, options);
  await PassboltSession.login(serverUrl, privateKey, passphrase);

  const views: ResourceView[] = await session.listResourceViews("github", true);
  const names: string[] = views.map((view) => view.name);
  const password: string | null | undefined = views[0]?.password;

  const newResource: NewResource = { name: "GitHub", username: "ada", uris: ["https://github.com"] };
  const created: Resource = await session.createResource(newResource);
  const changes: ResourceChanges = { password: "new", expired: null };
  await session.updateResource(created.id, changes);

  const folder: Folder = await session.createFolder("Ops", undefined);
  const tree: FolderTreeNode[] = await session.getFolderTree();
  const me: User = await session.getMe();
  const blockers: DeleteBlockers = await session.userDeleteBlockers(me.id);
  return { names, password, folder, tree, blockers: blockers.groups_to_delete };
}
