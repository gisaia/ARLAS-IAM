package io.arlas.iam.rest.model.output;

import io.arlas.iam.model.Organisation;
import io.arlas.iam.model.User;

import java.time.ZoneOffset;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.UUID;

public class UserData implements Comparable {
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
    public List<UserOrgData> organisations = new ArrayList<>();
    public List<RoleData> roles = new ArrayList<>();

    public UserData(User user) {
        this(user, true);
    }

    public UserData(User user, boolean showOrg) {
        this(user, null, showOrg);
    }

    public UserData(User user, Organisation org, boolean showOrg) {
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
        if (showOrg) {
            user.getOrganisations().forEach(o -> organisations.add(new UserOrgData(o.getOrganisation(), user)));
            Collections.sort(organisations);
        }
        user.getRoles().stream()
                .filter(r -> org == null
                        || (r.getOrganisation().isPresent() && r.getOrganisation().get().is(org))
                        || r.getOrganisation().isEmpty())
                .forEach(r -> roles.add(new RoleData(r)));
    }

    @Override
    public int compareTo(Object o) {
        return email.compareTo(((UserData) o).email);
    }

}
