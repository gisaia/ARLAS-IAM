package io.arlas.ums.task;

import com.fasterxml.jackson.databind.ObjectMapper;
import io.arlas.ums.config.InitConfiguration;
import io.arlas.ums.core.AuthService;
import io.dropwizard.hibernate.UnitOfWork;
import io.dropwizard.servlets.tasks.PostBodyTask;
import java.io.PrintWriter;
import java.util.List;
import java.util.Map;

public class InitDatabaseTask extends PostBodyTask {
    private AuthService authService;
    private static final ObjectMapper mapper = new ObjectMapper();

    public InitDatabaseTask(AuthService authService) {
        super("initdb");
        this.authService = authService;
    }

    @Override
    @UnitOfWork
    public void execute(Map<String, List<String>> map, String postBody, PrintWriter printWriter) throws Exception {
        authService.initDatabase(postBody.isBlank() ? new InitConfiguration() : mapper.reader().readValue(postBody, InitConfiguration.class));
    }
}