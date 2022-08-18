package io.arlas.iam.impl;

import io.arlas.iam.model.Organisation;
import io.arlas.iam.model.OrganisationMember;
import io.arlas.iam.model.User;
import io.arlas.iam.core.OrganisationMemberDao;
import io.dropwizard.hibernate.AbstractDAO;
import org.hibernate.SessionFactory;

import java.util.Optional;

public class HibernateOrganisationMemberDao extends AbstractDAO<OrganisationMember> implements OrganisationMemberDao {
    public HibernateOrganisationMemberDao(SessionFactory sessionFactory) {
        super(sessionFactory);
    }

    @Override
    public OrganisationMember updateUserInOrganisation(OrganisationMember user) {
        return persist(user);
    }

    @Override
    public Organisation addUserToOrganisation(User user, Organisation organisation, boolean isOwner) {
        organisation.addMember(persist(new OrganisationMember(user, organisation, isOwner)));
        return organisation;
    }

    @Override
    public Organisation removeUserFromOrganisation(User user, Organisation organisation) {
        Optional<OrganisationMember> omToRemove = organisation.getMembers().stream()
                .filter(om -> om.getUser().is(user.getId())).findFirst();
        omToRemove.ifPresent(om -> {
            currentSession().delete(om);
            organisation.removeMember(om);

        });
        return organisation;
    }
}
