package io.arlas.ums.impl;

import io.arlas.ums.core.PermissionDao;
import io.arlas.ums.model.Permission;
import io.dropwizard.hibernate.AbstractDAO;
import org.hibernate.SessionFactory;

import java.util.Optional;
import java.util.Set;
import java.util.UUID;
import java.util.stream.Collectors;

public class HibernatePermissionDao extends AbstractDAO<Permission> implements PermissionDao {
    public HibernatePermissionDao(SessionFactory sessionFactory) {
        super(sessionFactory);
    }

    @Override
    public Permission createPermission(Permission permission) {
        return persist(permission);
    }

    @Override
    public Set<Permission> savePermissions(Set<Permission> permissions) {
        return permissions.stream().map(p -> readPermission(p.getValue()).orElseGet(() -> createPermission(p)))
                .collect(Collectors.toSet());
    }

    @Override
    public Optional<Permission> readPermission(UUID permissionId) {
        return Optional.ofNullable(get(permissionId));
    }

    @Override
    public Optional<Permission> readPermission(String value) {
        return currentSession().byNaturalId(Permission.class).using("value", value).loadOptional();
    }
}
