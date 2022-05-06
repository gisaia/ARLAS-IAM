package io.arlas.iam.config;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.dataformat.yaml.YAMLFactory;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;

public class TechnicalRoles {
    // permissions of these roles are defined in arlas-iam-filter/src/main/resources/roles.yaml
    public static final String ROLE_IDP_ADMIN = "role/idp/admin";
    public static final String ROLE_ARLAS_OWNER = "role/arlas/owner";
    public static final String ROLE_ARLAS_USER = "role/arlas/user";
    public static final String ROLE_ARLAS_BUILDER = "role/arlas/builder";
    public static final String ROLE_ARLAS_TAGGER = "role/arlas/tagger";
    public static final String ROLE_ARLAS_IMPORTER = "role/arlas/importer";
    public static final String GROUP_PUBLIC = "group/public";

    private static final Logger LOGGER = LoggerFactory.getLogger(TechnicalRoles.class);
    private static final ObjectMapper mapper = new ObjectMapper(new YAMLFactory());
    private static Map<String, List<String>> technicalRolesPermissions;

    static {
        try {
            technicalRolesPermissions = (Map<String, List<String>>) mapper.readValue(
                            TechnicalRoles.class.getClassLoader().getResourceAsStream("roles.yaml"), Map.class)
                    .get("technicalRoles");
        } catch (IOException e) {
            technicalRolesPermissions = new HashMap<>();
            LOGGER.error("!-----! Technical roles file could not be read !-----!");
        }
    }

    public static Map<String, List<String>> getTechnicalRolesPermissions() {
        return technicalRolesPermissions;
    }

    public static Set<String> getTechnicalRolesList() {
        return technicalRolesPermissions.keySet();
    }

    public static String getDefaultGroup(String org) {
        return String.format("group/config.json/%s", org);
    }

    public static String getNewDashboardGroupRole(String org, String group) {
        return String.format("group/config.json/%s/%s", org, group);
    }
}
