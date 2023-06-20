package io.arlas.iam.rest.model.input;

import java.util.Set;

public class ApiKeyDef {
    public String name;
    public Set<String> roleIds;
    public int ttlInDays = 30;


}
