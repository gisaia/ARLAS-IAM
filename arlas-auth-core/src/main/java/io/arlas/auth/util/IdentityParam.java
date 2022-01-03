package io.arlas.auth.util;

import java.util.ArrayList;
import java.util.List;

public class IdentityParam {

    public String userId;
    public String organization;
    public List<String> groups;

    public IdentityParam(String userId, String organization, List<String> groups) {
        this.userId = userId;
        this.organization = organization;
        this.groups = groups != null ? groups : new ArrayList<>();
    }
}
