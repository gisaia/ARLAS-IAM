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

package io.arlas.iam.server;

import io.arlas.iam.core.AuthService;
import io.arlas.iam.rest.AbstractServer;
import io.arlas.iam.rest.service.IAMRestService;
import io.arlas.iam.util.ArlasAuthServerConfiguration;
import io.arlas.iam.util.InitDatabaseTask;
import io.dropwizard.core.setup.Environment;
import io.dropwizard.hibernate.UnitOfWorkAwareProxyFactory;

public class ArlasIamServer extends AbstractServer {

    public static void main(String... args) throws Exception {
        new ArlasIamServer().run(args);
    }

    @Override
    public void run(ArlasAuthServerConfiguration configuration, Environment environment) throws Exception {
        super.run(configuration, environment);
        environment.jersey().register(new IAMRestService(this.authService, configuration));

        InitDatabaseTask initDatabaseTask = new UnitOfWorkAwareProxyFactory(hibernate)
                .create(InitDatabaseTask.class, new Class[]{ AuthService.class }, new Object[]{ this.authService });
        initDatabaseTask.execute();
    }
}