package io.arlas.idp.server;

import io.arlas.iam.core.AuthService;
import io.arlas.iam.rest.service.UmsRestService;
import io.arlas.iam.server.AbstractServer;
import io.arlas.iam.util.InitDatabaseTask;
import io.arlas.iam.util.ArlasAuthServerConfiguration;
import io.dropwizard.hibernate.UnitOfWorkAwareProxyFactory;
import io.dropwizard.setup.Environment;

public class ArlasIdpServer extends AbstractServer {

    public static void main(String... args) throws Exception {
        new ArlasIdpServer().run(args);
    }

    @Override
    public void run(ArlasAuthServerConfiguration configuration, Environment environment) throws Exception {
        super.run(configuration, environment);
        environment.jersey().register(new UmsRestService(this.authService, configuration));

        InitDatabaseTask initDatabaseTask = new UnitOfWorkAwareProxyFactory(hibernate)
                .create(InitDatabaseTask.class, new Class[]{ AuthService.class }, new Object[]{ this.authService });
        initDatabaseTask.execute();
    }
}