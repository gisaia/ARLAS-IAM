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

import io.arlas.iam.core.ApiKeyDao;
import io.arlas.iam.model.ApiKey;
import io.dropwizard.hibernate.AbstractDAO;
import org.hibernate.SessionFactory;

import java.util.Optional;
import java.util.UUID;

public class HibernateApiKeyDao extends AbstractDAO<ApiKey> implements ApiKeyDao {

    public HibernateApiKeyDao(SessionFactory sessionFactory) {
        super(sessionFactory);
    }

    @Override
    public ApiKey createApiKey(ApiKey apiKey) {
        return persist(apiKey);
    }

    @Override
    public Optional<ApiKey> readApiKey(UUID id) {
        return Optional.ofNullable(get(id));
    }

    @Override
    public Optional<ApiKey> readApiKey(String keyId) {
        return currentSession().byNaturalId(ApiKey.class).using("keyId", keyId).loadOptional();
    }

    @Override
    public void deleteApiKey(ApiKey apiKey) {
        currentSession().remove(apiKey);
    }
}
