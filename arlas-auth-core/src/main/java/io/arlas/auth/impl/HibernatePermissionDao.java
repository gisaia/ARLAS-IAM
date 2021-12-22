package io.arlas.auth.impl;

import io.arlas.auth.core.PermissionDao;
import io.arlas.auth.model.Permission;
import io.dropwizard.hibernate.AbstractDAO;
import org.hibernate.SessionFactory;

public class HibernatePermissionDao extends AbstractDAO<Permission> implements PermissionDao {
    public HibernatePermissionDao(SessionFactory sessionFactory) {
        super(sessionFactory);
    }

    @Override
    public Permission createPermission(Permission permission) {
        return persist(permission);
    }
}
