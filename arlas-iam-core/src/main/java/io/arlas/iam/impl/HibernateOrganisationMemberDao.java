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

import io.arlas.iam.core.OrganisationMemberDao;
import io.arlas.iam.model.Organisation;
import io.arlas.iam.model.OrganisationMember;
import io.arlas.iam.model.User;
import io.dropwizard.hibernate.AbstractDAO;
import org.hibernate.SessionFactory;

import java.util.Optional;

public class HibernateOrganisationMemberDao extends AbstractDAO<OrganisationMember> implements OrganisationMemberDao {
    public HibernateOrganisationMemberDao(SessionFactory sessionFactory) {
        super(sessionFactory);
    }

    @Override
    public OrganisationMember updateUserInOrganisation(OrganisationMember user) {
        return persist(user);
    }

    @Override
    public Organisation addUserToOrganisation(User user, Organisation organisation, boolean isOwner, boolean isAdmin) {
        var om = persist(new OrganisationMember(user, organisation, isOwner, isAdmin));
        organisation.addMember(om);
        user.addOrganisation(om);
        return organisation;
    }

    @Override
    public Organisation removeUserFromOrganisation(User user, Organisation organisation) {
        Optional<OrganisationMember> omToRemove = organisation.getMembers().stream()
                .filter(om -> om.getUser().is(user.getId())).findFirst();
        omToRemove.ifPresent(om -> {
            currentSession().remove(om);
            organisation.removeMember(om);

        });
        return organisation;
    }
}
