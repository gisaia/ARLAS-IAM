package io.arlas.iam.rest.model.output;

import io.arlas.iam.model.User;

import java.time.ZoneOffset;
import java.util.ArrayList;
import java.util.List;
import java.util.UUID;

public class UserData {
    public UUID id;
    public String email;
    public String firstName;
    public String lastName;
    public String locale;
    public String timezone;
    public long creationDate;
    public long updateDate;
    public boolean isVerified;
    public boolean isActive;
    public List<OrgData> organisations = new ArrayList<>();
    public List<RoleData> roles = new ArrayList<>();

    public UserData(User user) {
        this.id = user.getId();
        this.email = user.getEmail();
        this.firstName = user.getFirstName();
        this.lastName = user.getLastName();
        this.locale = user.getLocale();
        this.timezone = user.getTimezone();
        this.creationDate = user.getCreationDate().toEpochSecond(ZoneOffset.UTC);
        this.updateDate = user.getUpdateDate().toEpochSecond(ZoneOffset.UTC);
        this.isVerified = user.isVerified();
        this.isActive = user.isActive();
        user.getOrganisations().forEach(o -> organisations.add(new OrgData(o.getOrganisation(), false)));
        user.getRoles().forEach(r -> roles.add(new RoleData(r)));
    }
}
