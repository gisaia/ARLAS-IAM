package io.arlas.auth.impl;

import io.arlas.auth.core.RoleDao;
import io.arlas.auth.model.Permission;
import io.arlas.auth.model.Role;
import io.arlas.auth.model.User;
import io.dropwizard.hibernate.AbstractDAO;
import org.hibernate.SessionFactory;

import java.util.Optional;
import java.util.Set;
import java.util.UUID;

public class HibernateRoleDao extends AbstractDAO<Role> implements RoleDao {
    public HibernateRoleDao(SessionFactory sessionFactory) {
        super(sessionFactory);
    }

    @Override
    public Role createRole(Role role, Set<Permission> permissions) {
        role.setPermissions(permissions);
        permissions.forEach(p -> p.getRoles().add(role));
        return persist(role);
    }

    @Override
    public Optional<Role> readRole(UUID roleId) {
        return Optional.ofNullable(get(roleId));
    }

    @Override
    public Role addRoleToUser(User user, Role role) {
        role.getUsers().add(user);
        user.getRoles().add(role);
        return persist(role);
    }

    @Override
    public Role removeRoleFromUser(User user, Role role) {
        role.getUsers().remove(user);
        user.getRoles().remove(role);
        return persist(role);
    }

    @Override
    public Role addPermissionToRole(Permission permission, Role role) {
        role.getPermissions().add(permission);
        permission.getRoles().add(role);
        return persist(role);
    }

    @Override
    public Role removePermissionFromRole(Permission permission, Role role) {
        role.getPermissions().remove(permission);
        permission.getRoles().remove(role);
        return persist(role);
    }

}
