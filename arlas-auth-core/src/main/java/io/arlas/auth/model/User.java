package io.arlas.auth.model;

import org.hibernate.annotations.NaturalId;

import javax.persistence.*;
import javax.validation.constraints.NotNull;
import java.time.LocalDateTime;
import java.time.ZoneOffset;
import java.util.*;

@Entity
@Table(name = "users")
public class User {

    @Id
    @GeneratedValue
    @Column
    private UUID id;

    @NaturalId
    @Column
    private String email;

    @Column
    private String password;

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

    @ManyToMany(mappedBy = "members")
    private Set<Group> groups = new HashSet<>();

    @ManyToMany(mappedBy="users")
    private Set<Role> roles = new HashSet<>();

    @ManyToMany(mappedBy="users")
    private Set<Permission> permissions = new HashSet<>();

    private User() {}

    public User(String email) {
        this.email = email;
    }

    public UUID getId() {
        return this.id;
    }

    private void setId(UUID id) {
        this.id = id;
    }

    public boolean is(UUID uuid) {
        return this.id.equals(uuid);
    }

    public String getEmail() {
        return email;
    }

    private void setEmail(String email) {
        this.email = email;
    }

    public String getPassword() {
        return password;
    }

    public void setPassword(String password) {
        this.password = password;
    }

    public String getFirstName() {
        return firstName;
    }

    public User setFirstName(String firstName) {
        this.firstName = firstName;
        return this;
    }

    public String getLastName() {
        return lastName;
    }

    public User setLastName(String lastName) {
        this.lastName = lastName;
        return this;
    }

    public String getLocale() {
        return locale;
    }

    public User setLocale(String locale) {
        this.locale = locale;
        return this;
    }

    public LocalDateTime getCreationDate() {
        return creationDate;
    }

    public void setCreationDate(LocalDateTime creationDate) {
        this.creationDate = creationDate;
    }

    public LocalDateTime getUpdateDate() {
        return updateDate;
    }

    public void setUpdateDate(LocalDateTime updateDate) {
        this.updateDate = updateDate;
    }

    public boolean isVerified() {
        return isVerified;
    }

    public User setVerified(boolean isVerified) {
        this.isVerified = isVerified;
        return this;
    }

    public boolean isActive() {
        return isActive;
    }

    public User setActive(boolean isActive) {
        this.isActive = isActive;
        return this;
    }

    public Set<OrganisationMember> getOrganisations() {
        return organisations;
    }

    public void setOrganisations(Set<OrganisationMember> organisations) {
        this.organisations = organisations;
    }

    public Set<Group> getGroups() {
        return groups;
    }

    public void setGroups(Set<Group> groups) {
        this.groups = groups;
    }

    public Set<Role> getRoles() {
        return roles;
    }

    public void setRoles(Set<Role> roles) {
        this.roles = roles;
    }

    public Set<Permission> getPermissions() {
        return permissions;
    }

    public void setPermissions(Set<Permission> permissions) {
        this.permissions = permissions;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        User user = (User) o;
        return getEmail().equals(user.getEmail());
    }

    @Override
    public int hashCode() {
        return Objects.hash(getEmail());
    }
}
