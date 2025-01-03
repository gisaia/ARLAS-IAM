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

package io.arlas.iam.rest;

import com.fasterxml.jackson.annotation.JsonInclude.Include;
import com.fasterxml.jackson.databind.DeserializationFeature;
import io.arlas.commons.cache.BaseCacheManager;
import io.arlas.commons.cache.CacheFactory;
import io.arlas.commons.config.ArlasAuthConfiguration;
import io.arlas.commons.config.ArlasConfiguration;
import io.arlas.commons.config.ArlasCorsConfiguration;
import io.arlas.commons.exceptions.ArlasExceptionMapper;
import io.arlas.commons.exceptions.ConstraintViolationExceptionMapper;
import io.arlas.commons.exceptions.IllegalArgumentExceptionMapper;
import io.arlas.commons.exceptions.JsonProcessingExceptionMapper;
import io.arlas.commons.rest.utils.InsensitiveCaseFilter;
import io.arlas.commons.rest.utils.PrettyPrintFilter;
import io.arlas.iam.core.AuthService;
import io.arlas.iam.impl.ArlasPolicyEnforcer;
import io.arlas.iam.impl.HibernateAuthService;
import io.arlas.iam.model.*;
import io.arlas.iam.util.ArlasAuthServerConfiguration;
import io.dropwizard.assets.AssetsBundle;
import io.dropwizard.configuration.EnvironmentVariableSubstitutor;
import io.dropwizard.configuration.SubstitutingSourceProvider;
import io.dropwizard.core.Application;
import io.dropwizard.core.setup.Bootstrap;
import io.dropwizard.core.setup.Environment;
import io.dropwizard.db.DataSourceFactory;
import io.dropwizard.hibernate.HibernateBundle;
import io.dropwizard.hibernate.UnitOfWorkAwareProxyFactory;
import io.federecio.dropwizard.swagger.SwaggerBundle;
import io.federecio.dropwizard.swagger.SwaggerBundleConfiguration;
import jakarta.servlet.DispatcherType;
import jakarta.servlet.FilterRegistration;
import jakarta.ws.rs.core.HttpHeaders;
import org.eclipse.jetty.servlets.CrossOriginFilter;
import org.glassfish.jersey.media.multipart.MultiPartFeature;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.EnumSet;

public abstract class AbstractServer extends Application<ArlasAuthServerConfiguration> {
    private final Logger LOGGER = LoggerFactory.getLogger(AbstractServer.class);
    protected AuthService authService;

    protected final HibernateBundle<ArlasAuthServerConfiguration> hibernate =
            new HibernateBundle<>(
                    ForbiddenOrganisation.class,
                    Organisation.class,
                    OrganisationMember.class,
                    Permission.class,
                    Role.class,
                    User.class,
                    TokenSecret.class,
                    RefreshToken.class,
                    ApiKey.class) {
                @Override
                public DataSourceFactory getDataSourceFactory(ArlasAuthServerConfiguration configuration) {
                    return configuration.database;
                }
            };

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
        LOGGER.info("Checked configuration: " + environment.getObjectMapper().writer().writeValueAsString(configuration));

        environment.getObjectMapper().setSerializationInclusion(Include.NON_NULL);
        environment.jersey().register(MultiPartFeature.class);
        environment.jersey().register(new ArlasExceptionMapper());
        environment.jersey().register(new IllegalArgumentExceptionMapper());
        environment.jersey().register(new JsonProcessingExceptionMapper());
        environment.jersey().register(new ConstraintViolationExceptionMapper());

        this.authService = new HibernateAuthService(hibernate.getSessionFactory(), configuration);

        CacheFactory cacheFactory = (CacheFactory) Class
                .forName(configuration.arlasCacheFactoryClass)
                .getConstructor(ArlasConfiguration.class)
                .newInstance(configuration);

        ArlasPolicyEnforcer arlasPolicyEnforcer = new UnitOfWorkAwareProxyFactory(hibernate)
                .create(ArlasPolicyEnforcer.class, new Class[]{ AuthService.class, ArlasAuthConfiguration.class, BaseCacheManager.class},
                        new Object[]{ this.authService, configuration.arlasAuthConfiguration, cacheFactory.getCacheManager() });
        environment.jersey().register(arlasPolicyEnforcer);

        //cors
        if (configuration.arlasCorsConfiguration.enabled) {
            configureCors(environment, configuration.arlasCorsConfiguration);
        } else {
            CrossOriginFilter filter = new CrossOriginFilter();
            final FilterRegistration.Dynamic cors = environment.servlets().addFilter("CrossOriginFilter", filter);
            // Expose always HttpHeaders.WWW_AUTHENTICATE to authenticate on client side a non public uri call
            cors.setInitParameter(CrossOriginFilter.EXPOSED_HEADERS_PARAM, HttpHeaders.WWW_AUTHENTICATE);
        }

        //filters
        environment.jersey().register(PrettyPrintFilter.class);
        environment.jersey().register(InsensitiveCaseFilter.class);
    }

    private void configureCors(Environment environment, ArlasCorsConfiguration configuration) {
        CrossOriginFilter filter = new CrossOriginFilter();
        final FilterRegistration.Dynamic cors = environment.servlets().addFilter("CrossOriginFilter", filter);
        // Configure CORS parameters
        cors.setInitParameter(CrossOriginFilter.ALLOWED_ORIGINS_PARAM, configuration.allowedOrigins);
        cors.setInitParameter(CrossOriginFilter.ALLOWED_HEADERS_PARAM, configuration.allowedHeaders);
        cors.setInitParameter(CrossOriginFilter.ALLOWED_METHODS_PARAM, configuration.allowedMethods);
        cors.setInitParameter(CrossOriginFilter.ALLOW_CREDENTIALS_PARAM, String.valueOf(configuration.allowedCredentials));
        String exposedHeader = configuration.exposedHeaders;
        // Expose always HttpHeaders.WWW_AUTHENTICATE to authentify on client side a non public uri call
        if (!configuration.exposedHeaders.contains(HttpHeaders.WWW_AUTHENTICATE)) {
            exposedHeader = configuration.exposedHeaders.concat(",").concat(HttpHeaders.WWW_AUTHENTICATE);
        }
        cors.setInitParameter(CrossOriginFilter.EXPOSED_HEADERS_PARAM, exposedHeader);

        // Add URL mapping
        cors.addMappingForUrlPatterns(EnumSet.allOf(DispatcherType.class), true, "/*");
    }
}
