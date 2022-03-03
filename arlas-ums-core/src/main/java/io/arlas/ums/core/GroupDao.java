package io.arlas.ums.core;

import io.arlas.ums.model.Group;
import io.arlas.ums.model.Role;
import io.arlas.ums.model.User;

public interface GroupDao {

    Group createGroup(Group group);

    Group addUserToGroup(User user, Group group);

    Group removeUserFromGroup(User user, Group group);

    Group addRoleToGroup(Role role, Group group);

    Group removeRoleFromGroup(Role role, Group group);

}
