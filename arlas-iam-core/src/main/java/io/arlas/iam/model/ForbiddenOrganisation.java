package io.arlas.iam.model;

import io.dropwizard.jackson.JsonSnakeCase;

import javax.persistence.*;
import java.util.Objects;

@Entity
@Table(name = "forbiddenOrganisation")
@JsonSnakeCase
public class ForbiddenOrganisation {
    @Id
    @Column
    public String name;

    public ForbiddenOrganisation(){}

    public ForbiddenOrganisation(String name) {
        this.name = name;
    }

    public String getName() {
        return name;
    }

    public void setName(String name) {
        this.name = name;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        ForbiddenOrganisation that = (ForbiddenOrganisation) o;
        return Objects.equals(getName(), that.getName());
    }

    @Override
    public int hashCode() {
        return Objects.hash(getName());
    }
}
