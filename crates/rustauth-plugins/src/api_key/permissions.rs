use std::collections::BTreeSet;

use super::options::ApiKeyPermissions;

pub fn allows(stored: Option<&ApiKeyPermissions>, required: Option<&ApiKeyPermissions>) -> bool {
    let Some(required) = required else {
        return true;
    };
    if required.is_empty() {
        return true;
    }
    let Some(stored) = stored else {
        return false;
    };

    required.iter().all(|(resource, actions)| {
        let Some(allowed) = stored.get(resource) else {
            return false;
        };
        let allowed = allowed.iter().collect::<BTreeSet<_>>();
        actions.iter().all(|action| allowed.contains(action))
    })
}
