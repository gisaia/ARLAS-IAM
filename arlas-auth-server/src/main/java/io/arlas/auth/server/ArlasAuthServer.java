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

import com.fasterxml.jackson.annotation.JsonInclude.Include;
import com.fasterxml.jackson.databind.DeserializationFeature;
import com.fasterxml.jackson.databind.ObjectMapper;
import io.arlas.auth.core.AuthService;
import io.arlas.auth.impl.HibernateAuthService;
import io.arlas.auth.model.*;
import io.arlas.auth.rest.service.AuthRestService;
import io.arlas.auth.util.ArlasAuthServerConfiguration;
import io.dropwizard.Application;
import io.dropwizard.assets.AssetsBundle;
import io.dropwizard.configuration.EnvironmentVariableSubstitutor;
import io.dropwizard.configuration.SubstitutingSourceProvider;
import io.dropwizard.db.DataSourceFactory;
import io.dropwizard.hibernate.HibernateBundle;
import io.dropwizard.jersey.jackson.JsonProcessingExceptionMapper;
import io.dropwizard.setup.Bootstrap;
import io.dropwizard.setup.Environment;
import io.federecio.dropwizard.swagger.SwaggerBundle;
import io.federecio.dropwizard.swagger.SwaggerBundleConfiguration;
import org.glassfish.jersey.media.multipart.MultiPartFeature;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class ArlasAuthServer extends Application<ArlasAuthServerConfiguration> {
    Logger LOGGER = LoggerFactory.getLogger(ArlasAuthServer.class);

    private final HibernateBundle<ArlasAuthServerConfiguration> hibernate =
            new HibernateBundle<ArlasAuthServerConfiguration>(
                    Group.class,
                    Organisation.class,
                    OrganisationMember.class,
                    Permission.class,
                    Role.class,
                    User.class) {
                @Override
                public DataSourceFactory getDataSourceFactory(ArlasAuthServerConfiguration configuration) {
                    return configuration.database;
                }
            };

    public static void main(String... args) throws Exception {
        new ArlasAuthServer().run(args);
    }

    @Override
    public void initialize(Bootstrap<ArlasAuthServerConfiguration> bootstrap) {
        bootstrap.registerMetrics();
        bootstrap.getObjectMapper().enable(DeserializationFeature.FAIL_ON_UNKNOWN_PROPERTIES);
        bootstrap.setConfigurationSourceProvider(new SubstitutingSourceProvider(
                bootstrap.getConfigurationSourceProvider(),
                new EnvironmentVariableSubstitutor(false))
        );
        bootstrap.addBundle(new SwaggerBundle<>() {
            @Override
            protected SwaggerBundleConfiguration getSwaggerBundleConfiguration(ArlasAuthServerConfiguration configuration) {
                return configuration.swaggerBundleConfiguration;
            }
        });
        bootstrap.addBundle(hibernate);
        bootstrap.addBundle(new AssetsBundle("/assets/", "/", "index.html"));
    }

    @Override
    public void run(ArlasAuthServerConfiguration configuration, Environment environment) throws Exception {

        configuration.check();
        LOGGER.info("Checked configuration: " + (new ObjectMapper()).writer().writeValueAsString(configuration));

        environment.getObjectMapper().setSerializationInclusion(Include.NON_NULL);
        environment.jersey().register(MultiPartFeature.class);
//        environment.jersey().register(new ArlasExceptionMapper());
//        environment.jersey().register(new IllegalArgumentExceptionMapper());
        environment.jersey().register(new JsonProcessingExceptionMapper());
//        environment.jersey().register(new ConstraintViolationExceptionMapper());

        AuthService authService = new HibernateAuthService(hibernate.getSessionFactory());
        environment.jersey().register(new AuthRestService(authService, configuration));

        // Auth
//        if (configuration.arlasAuthConfiguration.enabled) {
//            environment.jersey().register(new AuthenticationFilter(configuration.arlasAuthConfiguration));
//            environment.jersey().register(new AuthorizationFilter(configuration.arlasAuthConfiguration));
//        }

        //cors
//        if (configuration.arlasCorsConfiguration.enabled) {
//            configureCors(environment,configuration.arlasCorsConfiguration);
//        }else{
//            CrossOriginFilter filter = new CrossOriginFilter();
//            final FilterRegistration.Dynamic cors = environment.servlets().addFilter("CrossOriginFilter", filter);
//            // Expose always HttpHeaders.WWW_AUTHENTICATE to authentify on client side a non public uri call
//            cors.setInitParameter(CrossOriginFilter.EXPOSED_HEADERS_PARAM, HttpHeaders.WWW_AUTHENTICATE);
//        }

        //filters
//        environment.jersey().register(PrettyPrintFilter.class);
//        environment.jersey().register(InsensitiveCaseFilter.class);
    }

    // TODO
//    private void configureCors(Environment environment, ArlasCorsConfiguration configuration) {
//        CrossOriginFilter filter = new CrossOriginFilter();
//        final FilterRegistration.Dynamic cors = environment.servlets().addFilter("CrossOriginFilter", filter);
//        // Configure CORS parameters
//        cors.setInitParameter(CrossOriginFilter.ALLOWED_ORIGINS_PARAM, configuration.allowedOrigins);
//        cors.setInitParameter(CrossOriginFilter.ALLOWED_HEADERS_PARAM, configuration.allowedHeaders);
//        cors.setInitParameter(CrossOriginFilter.ALLOWED_METHODS_PARAM, configuration.allowedMethods);
//        cors.setInitParameter(CrossOriginFilter.ALLOW_CREDENTIALS_PARAM, String.valueOf(configuration.allowedCredentials));
//        String exposedHeader = configuration.exposedHeaders;
//        // Expose always HttpHeaders.WWW_AUTHENTICATE to authentify on client side a non public uri call
//        if(configuration.exposedHeaders.indexOf(HttpHeaders.WWW_AUTHENTICATE)<0){
//            exposedHeader = configuration.exposedHeaders.concat(",").concat(HttpHeaders.WWW_AUTHENTICATE);
//        }
//        cors.setInitParameter(CrossOriginFilter.EXPOSED_HEADERS_PARAM, exposedHeader);
//
//        // Add URL mapping
//        cors.addMappingForUrlPatterns(EnumSet.allOf(DispatcherType.class), true, "/*");
//    }
}
