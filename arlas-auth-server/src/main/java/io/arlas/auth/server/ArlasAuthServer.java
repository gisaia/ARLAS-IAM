package io.arlas.auth.server;

import io.arlas.ums.rest.service.auth.AuthRestService;
import io.arlas.ums.server.AbstractServer;
import io.arlas.ums.util.ArlasAuthServerConfiguration;
import io.dropwizard.setup.Environment;

public class ArlasAuthServer extends AbstractServer {

    public static void main(String... args) throws Exception {
        new ArlasAuthServer().run(args);
    }

    @Override
    public void run(ArlasAuthServerConfiguration configuration, Environment environment) throws Exception {
        super.run(configuration, environment);
        environment.jersey().register(new AuthRestService(this.authService, configuration));
    }
}