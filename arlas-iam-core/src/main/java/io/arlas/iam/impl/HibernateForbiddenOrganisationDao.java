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

import io.arlas.iam.core.ForbiddenOrganisationDao;
import io.arlas.iam.model.ForbiddenOrganisation;
import io.dropwizard.hibernate.AbstractDAO;
import org.hibernate.SessionFactory;

import java.util.List;
import java.util.Optional;

public class HibernateForbiddenOrganisationDao extends AbstractDAO<ForbiddenOrganisation> implements ForbiddenOrganisationDao {
    public HibernateForbiddenOrganisationDao(SessionFactory sessionFactory) {
        super(sessionFactory);
    }

    @Override
    public Optional<ForbiddenOrganisation> getName(String name) {
        return Optional.ofNullable(get(name));
    }

    @Override
    public ForbiddenOrganisation addName(ForbiddenOrganisation name) {
        return persist(name);
    }

    @Override
    public List<ForbiddenOrganisation> listNames() {
        return query("SELECT u FROM ForbiddenOrganisation u").getResultList();
    }

    @Override
    public void removeName(ForbiddenOrganisation name) {
        currentSession().remove(name);
    }
}
