package io.arlas.iam.util;

import java.util.ArrayList;
import java.util.List;

public class IdentityParam {

    public final String userId;
    public final List<String> groups;

    public IdentityParam(String userId, List<String> groups) {
        this.userId = userId;
        this.groups = groups != null ? groups : new ArrayList<>();
    }
}
