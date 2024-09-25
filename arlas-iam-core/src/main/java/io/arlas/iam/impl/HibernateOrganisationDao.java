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

import io.arlas.iam.core.OrganisationDao;
import io.arlas.iam.model.Organisation;
import io.arlas.iam.model.OrganisationMember;
import io.dropwizard.hibernate.AbstractDAO;
import org.hibernate.SessionFactory;

import java.util.Optional;
import java.util.Set;
import java.util.UUID;

public class HibernateOrganisationDao extends AbstractDAO<Organisation> implements OrganisationDao {
    public HibernateOrganisationDao(SessionFactory sessionFactory) {
        super(sessionFactory);
    }

    @Override
    public Organisation createOrganisation(Organisation organisation) {
        return persist(organisation);
    }

    @Override
    public Optional<Organisation> readOrganisation(UUID orgId) {
        return Optional.ofNullable(get(orgId));
    }

    @Override
    public Optional<Organisation> readOrganisation(String name) {
        return currentSession().byNaturalId(Organisation.class).using("name", name).loadOptional();
    }

    @Override
    public void deleteOrganisation(Organisation organisation) {
        currentSession().remove(organisation);
    }

    @Override
    public Set<OrganisationMember> listUsers(Organisation organisation) {
        return organisation.getMembers();
    }

    @Override
    public Set<Organisation> listOrganisations() {
        return Set.copyOf(query("SELECT o FROM Organisation o").getResultList());
    }
}
