package io.arlas.ums.util;

import io.arlas.ums.core.AuthService;
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