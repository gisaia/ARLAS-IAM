package io.arlas.iam.impl;

import io.arlas.iam.core.PermissionDao;
import io.arlas.iam.model.Permission;
import io.dropwizard.hibernate.AbstractDAO;
import org.hibernate.SessionFactory;

import java.util.Optional;

public class HibernatePermissionDao extends AbstractDAO<Permission> implements PermissionDao {
    public HibernatePermissionDao(SessionFactory sessionFactory) {
        super(sessionFactory);
    }

    @Override
    public Permission createPermission(Permission permission) {
        return persist(permission);
    }
}
