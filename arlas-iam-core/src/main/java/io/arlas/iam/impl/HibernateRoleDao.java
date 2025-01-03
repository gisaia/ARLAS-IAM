/*
 * Licensed to Gisaïa under one or more contributor
 * license agreements. See the NOTICE.txt file distributed with
 * this work for additional information regarding copyright
 * ownership. Gisaïa licenses this file to you under
 * the Apache License, Version 2.0 (the "License"); you may
 * not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *    http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */

package io.arlas.iam.impl;

import io.arlas.iam.core.RoleDao;
import io.arlas.iam.model.Permission;
import io.arlas.iam.model.Role;
import io.arlas.iam.model.User;
import io.dropwizard.hibernate.AbstractDAO;
import org.hibernate.SessionFactory;

import java.util.List;
import java.util.Optional;
import java.util.UUID;

public class HibernateRoleDao extends AbstractDAO<Role> implements RoleDao {
    public HibernateRoleDao(SessionFactory sessionFactory) {
        super(sessionFactory);
    }

    @Override
    public Role createOrUpdateRole(Role role) {
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

    @Override
    public List<Role> getSystemRoles() {
        return query("SELECT r FROM Role r WHERE r.isSystem = :system")
                .setCacheable(true)
                .setParameter("system", Boolean.TRUE)
                .list();
    }

    @Override
    public void deleteRole(Role role) {
        currentSession().remove(role);
    }

}
