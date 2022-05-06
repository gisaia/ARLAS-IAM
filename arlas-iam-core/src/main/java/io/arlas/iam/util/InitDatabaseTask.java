package io.arlas.iam.util;

import io.arlas.iam.core.AuthService;
import io.dropwizard.hibernate.UnitOfWork;

public class InitDatabaseTask {
    private final AuthService authService;

    public InitDatabaseTask(AuthService authService) {
        this.authService = authService;
    }

    @UnitOfWork
    public void execute() throws Exception {
        authService.initDatabase();
    }
}