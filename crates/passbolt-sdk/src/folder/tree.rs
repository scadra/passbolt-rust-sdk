// Passbolt ~ Open source password manager for teams
// Copyright (c) Passbolt SA (https://www.passbolt.com)
//
// Licensed under GNU Affero General Public License version 3 of the or any later version.
// For full copyright and license information, please see the LICENSE
// Redistributions of files must retain the above copyright notice.
//
// @copyright     Copyright (c) Passbolt SA (https://www.passbolt.com)
// @license       https://opensource.org/licenses/AGPL-3.0 AGPL License
// @link          https://www.passbolt.com Passbolt(tm)
// @since         0.1.0

use std::collections::{HashMap, HashSet, VecDeque};

use crate::types::{Folder, FolderTreeNode};

/// Build a hierarchical folder tree from a flat list of folders.
///
/// Root-level folders (those with no parent or whose parent is not in the list)
/// become top-level nodes. Returns a forest (multiple roots are possible).
fn build_subtree<'a>(
    parent_id: Option<&str>,
    children_map: &HashMap<Option<&'a str>, Vec<&'a Folder>>,
) -> Vec<FolderTreeNode> {
    let Some(children) = children_map.get(&parent_id) else {
        return Vec::new();
    };
    children
        .iter()
        .map(|&folder| FolderTreeNode {
            children: build_subtree(Some(&folder.id), children_map),
            folder: folder.clone(),
        })
        .collect()
}

#[must_use]
pub fn build_folder_tree(folders: &[Folder]) -> Vec<FolderTreeNode> {
    if folders.is_empty() {
        return Vec::new();
    }

    let id_set: HashSet<&str> = folders.iter().map(|folder| folder.id.as_str()).collect();

    let mut children_map: HashMap<Option<&str>, Vec<&Folder>> = HashMap::new();
    for folder in folders {
        let parent = folder
            .folder_parent_id
            .as_deref()
            .filter(|parent_id| id_set.contains(parent_id));
        children_map.entry(parent).or_default().push(folder);
    }

    build_subtree(None, &children_map)
}

/// Collect all folder IDs in the subtree rooted at `root_id` (inclusive).
#[must_use]
pub fn collect_subtree_ids(root_id: &str, folders: &[Folder]) -> HashSet<String> {
    let mut ids = HashSet::new();
    let mut queue = VecDeque::new();
    queue.push_back(root_id.to_owned());
    while let Some(current) = queue.pop_front() {
        // A folder seen already ends the branch: parent links forming a cycle loop no more.
        if folders.iter().any(|folder| folder.id == current) && ids.insert(current.clone()) {
            for child in folders.iter().filter(|candidate| {
                candidate
                    .folder_parent_id
                    .as_deref()
                    .is_some_and(|parent_id| parent_id == current)
            }) {
                queue.push_back(child.id.clone());
            }
        }
    }
    ids
}

/// Flatten a folder tree back into BFS-ordered folders (parents before children).
#[must_use]
pub fn flatten_tree(roots: &[FolderTreeNode]) -> Vec<&Folder> {
    let mut result = Vec::new();
    let mut queue: VecDeque<&FolderTreeNode> = roots.iter().collect();
    while let Some(node) = queue.pop_front() {
        result.push(&node.folder);
        for child in &node.children {
            queue.push_back(child);
        }
    }
    result
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_folder(id: &str, parent: Option<&str>) -> Folder {
        Folder {
            id: id.into(),
            name: id.into(),
            folder_parent_id: parent.map(String::from),
            created: None,
            modified: None,
            created_by: None,
            modified_by: None,
            personal: None,
            permission: None,
            permissions: Vec::new(),
        }
    }

    #[test]
    fn test_empty_list() {
        let tree = build_folder_tree(&[]);
        assert!(tree.is_empty());
    }

    #[test]
    fn test_flat_list_all_roots() {
        let folders = vec![make_folder("a", None), make_folder("b", None)];
        let tree = build_folder_tree(&folders);
        assert_eq!(tree.len(), 2);
        assert!(tree.iter().all(|node| node.children.is_empty()));
    }

    #[test]
    fn test_nested_hierarchy() {
        let folders = vec![
            make_folder("root", None),
            make_folder("child1", Some("root")),
            make_folder("child2", Some("root")),
            make_folder("grandchild", Some("child1")),
        ];
        let tree = build_folder_tree(&folders);
        assert_eq!(tree.len(), 1);
        assert_eq!(tree[0].folder.id, "root");
        assert_eq!(tree[0].children.len(), 2);

        let child1 = tree[0]
            .children
            .iter()
            .find(|node| node.folder.id == "child1")
            .expect("child1");
        assert_eq!(child1.children.len(), 1);
        assert_eq!(child1.children[0].folder.id, "grandchild");
    }

    #[test]
    fn test_orphan_parent_becomes_root() {
        // Parent "missing" is not in the list — child becomes a root
        let folders = vec![make_folder("orphan", Some("missing"))];
        let tree = build_folder_tree(&folders);
        assert_eq!(tree.len(), 1);
        assert_eq!(tree[0].folder.id, "orphan");
    }

    #[test]
    fn test_collect_subtree_ids() {
        let folders = vec![
            make_folder("root", None),
            make_folder("child1", Some("root")),
            make_folder("child2", Some("root")),
            make_folder("grandchild", Some("child1")),
            make_folder("other", None),
        ];
        let ids = collect_subtree_ids("root", &folders);
        assert_eq!(ids.len(), 4);
        assert!(ids.contains("root"));
        assert!(ids.contains("child1"));
        assert!(ids.contains("child2"));
        assert!(ids.contains("grandchild"));
        assert!(!ids.contains("other"));
    }

    #[test]
    fn test_collect_subtree_ids_ends_on_a_cycle() {
        let folders = vec![
            make_folder("first", Some("second")),
            make_folder("second", Some("first")),
        ];

        assert_eq!(collect_subtree_ids("first", &folders).len(), 2);
    }

    #[test]
    fn test_flatten_tree() {
        let folders = vec![
            make_folder("root", None),
            make_folder("child", Some("root")),
            make_folder("grandchild", Some("child")),
        ];
        let tree = build_folder_tree(&folders);
        let flat = flatten_tree(&tree);
        assert_eq!(flat.len(), 3);
        assert_eq!(flat[0].id, "root");
        assert_eq!(flat[1].id, "child");
        assert_eq!(flat[2].id, "grandchild");
    }
}
