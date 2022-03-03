package io.arlas.ums.impl;

import io.arlas.ums.core.GroupDao;
import io.arlas.ums.model.Group;
import io.arlas.ums.model.Role;
import io.arlas.ums.model.User;
import io.dropwizard.hibernate.AbstractDAO;
import org.hibernate.SessionFactory;

public class HibernateGroupDao extends AbstractDAO<Group> implements GroupDao {
    public HibernateGroupDao(SessionFactory sessionFactory) {
        super(sessionFactory);
    }

    @Override
    public Group createGroup(Group group) {
        return persist(group);
    }

    @Override
    public Group addUserToGroup(User user, Group group) {
        group.getMembers().add(user);
        user.getGroups().add(group);
        return persist(group);
    }

    @Override
    public Group removeUserFromGroup(User user, Group group) {
        group.getMembers().remove(user);
        user.getGroups().remove(group);
        return persist(group);
    }

    @Override
    public Group addRoleToGroup(Role role, Group group) {
        group.getRoles().add(role);
        role.getGroups().add(group);
        return persist(group);
    }

    @Override
    public Group removeRoleFromGroup(Role role, Group group) {
        group.getRoles().remove(role);
        role.getGroups().remove(group);
        return persist(group);
    }
}
