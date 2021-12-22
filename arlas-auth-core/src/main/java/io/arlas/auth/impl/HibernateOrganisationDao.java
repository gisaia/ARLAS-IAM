package io.arlas.auth.impl;

import io.arlas.auth.core.OrganisationDao;
import io.arlas.auth.model.Organisation;
import io.arlas.auth.model.User;
import io.dropwizard.hibernate.AbstractDAO;
import org.hibernate.SessionFactory;

import java.util.Set;
import java.util.stream.Collectors;

public class HibernateOrganisationDao extends AbstractDAO<Organisation> implements OrganisationDao {
    public HibernateOrganisationDao(SessionFactory sessionFactory) {
        super(sessionFactory);
    }

    @Override
    public Organisation createOrganisation(Organisation organisation) {
        // TODO register owner as organisationMember
        return persist(organisation);
    }

    @Override
    public Organisation deleteOrganisation(Organisation organisation) {
        // TODO check that user is owner
        currentSession().delete(organisation);
        return organisation;
    }

    @Override
    public Set<User> listUsers(User user) {
        return user.getOrganisations().stream()
                .flatMap(om -> om.getOrganisation().getMembers().stream())
                .map(om -> om.getUser())
                .collect(Collectors.toSet());
    }
}
