package io.arlas.auth.impl;

import io.arlas.auth.core.RoleDao;
import io.arlas.auth.model.Permission;
import io.arlas.auth.model.Role;
import io.arlas.auth.model.User;
import io.dropwizard.hibernate.AbstractDAO;
import org.hibernate.SessionFactory;

import java.util.List;
import java.util.Set;

public class HibernateRoleDao extends AbstractDAO<Role> implements RoleDao {
    public HibernateRoleDao(SessionFactory sessionFactory) {
        super(sessionFactory);
    }

    @Override
    public Role createRole(Role role, Set<Permission> permissions) {
        role.setPermissions(permissions);
        return persist(role);
    }

    @Override
    public Role addRoleToUser(User user, Role role) {
        role.getUsers().add(user);
        return persist(role);
    }

    @Override
    public Role removeRoleFromUser(User user, Role role) {
        role.getUsers().remove(user);
        return persist(role);
    }

}
