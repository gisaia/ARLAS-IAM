package io.arlas.ums.config;

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
}
