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

package io.arlas.auth.server;

import com.fasterxml.jackson.annotation.JsonProperty;
import io.dropwizard.Configuration;
import io.dropwizard.db.DataSourceFactory;
import io.federecio.dropwizard.swagger.SwaggerBundleConfiguration;

import javax.validation.Valid;
import javax.validation.constraints.NotNull;

public class ArlasAuthServerConfiguration extends Configuration {
    @JsonProperty("swagger")
    public SwaggerBundleConfiguration swaggerBundleConfiguration;

    @Valid
    @JsonProperty("database")
    public DataSourceFactory database = new DataSourceFactory();

    @JsonProperty("arlas-base-uri")
    public String arlasBaseUri;

    //    @JsonProperty("arlas_cors")
//    public ArlasCorsConfiguration arlarsCorsConfiguration;

    @NotNull
    @JsonProperty("arlas_organization_header")
    public String organizationHeader;

    @JsonProperty("anonymous_value")
    public String anonymousValue;

    public static final String FLATTEN_CHAR = "_";

    public void check() /*throws ArlasConfigurationException*/ {
//        if (swaggerBundleConfiguration == null) {
//            throw new ArlasConfigurationException("Swagger configuration missing in config file.");
//        }
//        if (arlasAuthConfiguration == null) {
//            arlasAuthConfiguration = new ArlasAuthConfiguration();
//            arlasAuthConfiguration.enabled = false;
//        } else {
//            arlasAuthConfiguration.check();
//        }
//        if (arlarsCorsConfiguration == null) {
//            arlarsCorsConfiguration = new ArlasCorsConfiguration();
//            arlarsCorsConfiguration.enabled = false;
//        }
//        if (arlasDatabaseFactoryClass == null) {
//            throw new ArlasConfigurationException("arlas_database_factory_class is missing");
//        }
//        if (arlasCacheFactoryClass == null) {
//            throw new ArlasConfigurationException("arlas_cache_factory_class is missing");
//        }
    }
}
