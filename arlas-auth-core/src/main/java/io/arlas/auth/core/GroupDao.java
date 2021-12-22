package io.arlas.auth.core;

import io.arlas.auth.model.Group;
import io.arlas.auth.model.Role;
import io.arlas.auth.model.User;

public interface GroupDao {

    Group createGroup(Group group);

    Group addUserToGroup(User user, Group group);

    Group removeUserFromGroup(User user, Group group);

    Group addRoleToGroup(Role role, Group group);

    Group removeRoleFromGroup(Role role, Group group);

}
