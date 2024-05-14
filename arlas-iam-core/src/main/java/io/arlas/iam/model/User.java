package io.arlas.iam.model;

import com.fasterxml.jackson.annotation.JsonIdentityInfo;
import com.fasterxml.jackson.annotation.JsonIgnore;
import com.fasterxml.jackson.annotation.ObjectIdGenerators;
import io.dropwizard.jackson.JsonSnakeCase;
import org.hibernate.annotations.NaturalId;

import jakarta.persistence.*;

import java.time.LocalDateTime;
import java.time.ZoneOffset;
import java.util.*;

@Entity
@Table(name = "users")
@JsonSnakeCase
@JsonIdentityInfo(generator = ObjectIdGenerators.PropertyGenerator.class, property="id")
public class User {

    @Id
    @GeneratedValue
    @Column
    private UUID id;

    @NaturalId
    @Column
    private String email;

    @Column
    @JsonIgnore
    private String password;

    @Column
    @JsonIgnore
    private String tempToken;

    @Column
    private String firstName;

    @Column
    private String lastName;

    @Column
    private String locale = Locale.ENGLISH.toString();

    @Column
    private String timezone = "Europe/Paris";

    @Column
    private LocalDateTime creationDate = LocalDateTime.now(ZoneOffset.UTC);

    @Column
    private LocalDateTime updateDate = LocalDateTime.now(ZoneOffset.UTC);

    @Column
    private boolean isVerified = false;

    @Column
    private boolean isActive = true;

    @OneToMany(mappedBy = "pk.user", cascade= CascadeType.REMOVE)
    private Set<OrganisationMember> organisations = new HashSet<>();

    @ManyToMany(mappedBy="users")
    private Set<Role> roles = new HashSet<>();

    @OneToMany(mappedBy="owner", cascade = CascadeType.REMOVE)
    private Set<ApiKey> apiKeys = new HashSet<>();

    private User() {}

    public User(String email) {
        this.email = email;
    }

    @PreRemove
    private void removeRoleAssociations() {
        for (Role role : this.roles) {
            role.getUsers().remove(this);
        }
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

    public String getTempToken() {
        return tempToken;
    }

    public void setTempToken(String tempToken) {
        this.tempToken = tempToken;
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

    public String getTimezone() {
        return timezone;
    }

    public void setTimezone(String timezone) {
        this.timezone = timezone;
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

    public void addOrganisation(OrganisationMember om) {
        this.organisations.add(om);
    }

    public Set<Role> getRoles() {
        return roles;
    }

    public void setRoles(Set<Role> roles) {
        this.roles = roles;
    }

    public Set<ApiKey> getApiKeys() {
        return apiKeys;
    }

    public void addApiKey(ApiKey apiKey) {
        this.apiKeys.add(apiKey);
    }

    public void setApiKeys(Set<ApiKey> apiKeys) {
        this.apiKeys = apiKeys;
    }

    public User updateLastUpdate() {
        this.updateDate = LocalDateTime.now(ZoneOffset.UTC);
        return this;
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
