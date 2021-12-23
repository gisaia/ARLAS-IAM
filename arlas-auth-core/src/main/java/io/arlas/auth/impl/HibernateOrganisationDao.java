package io.arlas.auth.impl;

import io.arlas.auth.core.OrganisationDao;
import io.arlas.auth.model.Organisation;
import io.arlas.auth.model.User;
import io.dropwizard.hibernate.AbstractDAO;
import org.hibernate.SessionFactory;

import java.util.Optional;
import java.util.Set;
import java.util.stream.Collectors;

public class HibernateOrganisationDao extends AbstractDAO<Organisation> implements OrganisationDao {
    public HibernateOrganisationDao(SessionFactory sessionFactory) {
        super(sessionFactory);
    }

    @Override
    public Organisation createOrganisation(Organisation organisation) {
        return persist(organisation);
    }

    @Override
    public Optional<Organisation> readOrganisation(Integer orgId) {
        return Optional.ofNullable(get(orgId));
    }

    @Override
    public Optional<Organisation> readOrganisation(String name) {
        return Optional.ofNullable(currentSession()
                .createQuery("from Organisation o where o." + Organisation.nameColumn + "=:name", Organisation.class)
                .setParameter("name", name)
                .uniqueResult());
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
