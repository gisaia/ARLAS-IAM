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