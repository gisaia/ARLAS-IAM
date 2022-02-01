package io.arlas.auth.model;

import com.fasterxml.jackson.annotation.JsonIgnore;
import io.dropwizard.jackson.JsonSnakeCase;
import org.hibernate.annotations.NaturalId;

import javax.persistence.*;
import java.util.UUID;

@Entity
@Table(name = "refreshToken")
@JsonSnakeCase
public class RefreshToken {
    @Id
    @Column
    @JsonIgnore
    protected UUID userId;

    @NaturalId
    @Column
    protected String value;

    @Column
    protected Long expiryDate;

    private RefreshToken() {}

    public RefreshToken(UUID subject, String refreshToken, long refreshTokenExpiryDate) {
        this.userId = subject;
        this.value = refreshToken;
        this.expiryDate = refreshTokenExpiryDate;
    }

    public UUID getUserId() {
        return userId;
    }

    public void setUserId(UUID userId) {
        this.userId = userId;
    }

    public String getValue() {
        return value;
    }

    public void setValue(String value) {
        this.value = value;
    }

    public Long getExpiryDate() {
        return expiryDate;
    }

    public void setExpiryDate(Long expiryDate) {
        this.expiryDate = expiryDate;
    }
}
