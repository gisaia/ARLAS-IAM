package io.arlas.auth.model;

import javax.persistence.*;
import javax.validation.constraints.NotNull;
import java.time.LocalDateTime;
import java.time.ZoneOffset;
import java.util.HashSet;
import java.util.Locale;
import java.util.Set;

@Entity
@Table(name = "user")
public class User {
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    @Column
    private Integer id;

    @NotNull
    @Column(unique = true)
    private String email;

    @Column
    private String firstName;

    @Column
    private String lastName;

    @Column
    private String locale = Locale.ENGLISH.toString();

    @Column
    private LocalDateTime creationDate = LocalDateTime.now(ZoneOffset.UTC);

    @Column
    private LocalDateTime updateDate = LocalDateTime.now(ZoneOffset.UTC);

    @Column
    private boolean isVerified = false;

    @Column
    private boolean isActive = true;

    @OneToMany(mappedBy = "pk.user")
    private Set<OrganisationMember> organisations = new HashSet<>();

    public Integer getId() {
        return this.id;
    }

    public String getEmail() {
        return email;
    }

    public void setEmail(String email) {
        this.email = email;
    }

    public String getFirstName() {
        return firstName;
    }

    public void setFirstName(String firstName) {
        this.firstName = firstName;
    }

    public String getLastName() {
        return lastName;
    }

    public void setLastName(String lastName) {
        this.lastName = lastName;
    }

    public String getLocale() {
        return locale;
    }

    public void setLocale(String locale) {
        this.locale = locale;
    }

    public LocalDateTime getCreationDate() {
        return creationDate;
    }

    public void setCreationDate(LocalDateTime creationDate) {
        this.creationDate = creationDate;
    }

    public LocalDateTime getLastUpdateDate() {
        return updateDate;
    }

    public void setLastUpdateDate(LocalDateTime updateDate) {
        this.updateDate = updateDate;
    }

    public boolean isVerified() {
        return isVerified;
    }

    public void setVerified(boolean isVerified) {
        this.isVerified = isVerified;
    }

    public boolean isActive() {
        return isActive;
    }

    public void setActive(boolean isActive) {
        this.isActive = isActive;
    }

    public Set<OrganisationMember> getOrganisations() {
        return organisations;
    }

    public void setOrganisations(Set<OrganisationMember> organisations) {
        this.organisations = organisations;
    }
}
