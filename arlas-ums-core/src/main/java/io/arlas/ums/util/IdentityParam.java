package io.arlas.ums.util;

import java.util.ArrayList;
import java.util.List;

public class IdentityParam {

    public final String userId;
    public final String organization;
    public final List<String> groups;

    public IdentityParam(String userId, String organization, List<String> groups) {
        this.userId = userId;
        this.organization = organization;
        this.groups = groups != null ? groups : new ArrayList<>();
    }
}
