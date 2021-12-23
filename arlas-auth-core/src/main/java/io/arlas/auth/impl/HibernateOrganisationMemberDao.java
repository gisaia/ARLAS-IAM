package io.arlas.auth.impl;

import io.arlas.auth.core.OrganisationMemberDao;
import io.arlas.auth.model.Organisation;
import io.arlas.auth.model.OrganisationMember;
import io.arlas.auth.model.User;
import io.dropwizard.hibernate.AbstractDAO;
import org.hibernate.SessionFactory;

import java.util.Optional;

public class HibernateOrganisationMemberDao extends AbstractDAO<OrganisationMember> implements OrganisationMemberDao {
    public HibernateOrganisationMemberDao(SessionFactory sessionFactory) {
        super(sessionFactory);
    }

    @Override
    public Organisation addUserToOrganisation(User user, Organisation organisation, boolean isOwner) {
        organisation.addMember(persist(new OrganisationMember(user, organisation, isOwner)));
        return organisation;
    }

    @Override
    public Organisation removeUserFromOrganisation(User user, Organisation organisation) {
        Optional<OrganisationMember> omToRemove = organisation.getMembers().stream()
                .filter(om -> om.getUser().getId() == user.getId()).findFirst();
        omToRemove.ifPresent(om -> {
            currentSession().delete(om);
            organisation.removeMember(om);

        });
        return organisation;
    }
}
