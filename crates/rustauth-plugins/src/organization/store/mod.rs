use rustauth_core::crypto::random::generate_random_string;
use rustauth_core::db::{
    Count, Create, DbAdapter, DbRecord, DbValue, Delete, DeleteMany, FindMany, FindOne, Sort,
    SortDirection, Update, Where, WhereOperator,
};
use rustauth_core::error::RustAuthError;
use time::OffsetDateTime;

use super::models::{required_string, Invitation, InvitationStatus, Member, Organization};
use super::record::{
    invitation_from_record, member_from_record, organization_from_record, user_from_record,
};

mod roles;
mod session;
mod teams;

pub(super) const ID_LENGTH: usize = 32;

pub struct OrganizationStore<'a> {
    adapter: &'a dyn DbAdapter,
}

impl<'a> OrganizationStore<'a> {
    pub fn new(adapter: &'a dyn DbAdapter) -> Self {
        Self { adapter }
    }

    pub fn adapter(&self) -> &'a dyn DbAdapter {
        self.adapter
    }

    pub async fn create_organization(
        &self,
        name: String,
        slug: String,
        logo: Option<String>,
        metadata: Option<serde_json::Value>,
        additional_fields: DbRecord,
    ) -> Result<Organization, RustAuthError> {
        let now = OffsetDateTime::now_utc();
        let mut query = Create::new("organization")
            .data("id", DbValue::String(generate_random_string(ID_LENGTH)))
            .data("name", DbValue::String(name))
            .data("slug", DbValue::String(slug))
            .data("created_at", DbValue::Timestamp(now))
            .data("updated_at", DbValue::Null)
            .force_allow_id();
        query = query.data("logo", option_string(logo));
        query = query.data(
            "metadata",
            metadata.map(DbValue::Json).unwrap_or(DbValue::Null),
        );
        for (field, value) in additional_fields {
            query = query.data(field, value);
        }
        organization_from_record(&self.adapter.create(query).await?)
    }

    pub async fn organization_by_slug(
        &self,
        slug: &str,
    ) -> Result<Option<Organization>, RustAuthError> {
        self.adapter
            .find_one(
                FindOne::new("organization")
                    .where_clause(Where::new("slug", DbValue::String(slug.to_owned()))),
            )
            .await?
            .map(|record| organization_from_record(&record))
            .transpose()
    }

    pub async fn organization_by_id(
        &self,
        id: &str,
    ) -> Result<Option<Organization>, RustAuthError> {
        self.adapter
            .find_one(FindOne::new("organization").where_clause(id_where(id)))
            .await?
            .map(|record| organization_from_record(&record))
            .transpose()
    }

    pub async fn update_organization(
        &self,
        id: &str,
        data: OrganizationUpdate,
    ) -> Result<Option<Organization>, RustAuthError> {
        let mut query = Update::new("organization")
            .where_clause(id_where(id))
            .data("updated_at", DbValue::Timestamp(OffsetDateTime::now_utc()));
        if let Some(name) = data.name {
            query = query.data("name", DbValue::String(name));
        }
        if let Some(slug) = data.slug {
            query = query.data("slug", DbValue::String(slug));
        }
        if data.logo_set {
            query = query.data("logo", option_string(data.logo));
        }
        if data.metadata_set {
            query = query.data(
                "metadata",
                data.metadata.map(DbValue::Json).unwrap_or(DbValue::Null),
            );
        }
        for (field, value) in data.additional_fields {
            query = query.data(field, value);
        }
        self.adapter
            .update(query)
            .await?
            .map(|record| organization_from_record(&record))
            .transpose()
    }

    pub async fn delete_organization(&self, id: &str) -> Result<(), RustAuthError> {
        self.adapter
            .delete_many(DeleteMany::new("member").where_clause(Where::new(
                "organization_id",
                DbValue::String(id.to_owned()),
            )))
            .await?;
        self.adapter
            .delete_many(DeleteMany::new("invitation").where_clause(Where::new(
                "organization_id",
                DbValue::String(id.to_owned()),
            )))
            .await?;
        self.adapter
            .delete(Delete::new("organization").where_clause(id_where(id)))
            .await
    }

    pub async fn create_member(
        &self,
        organization_id: &str,
        user_id: &str,
        role: &str,
        additional_fields: DbRecord,
    ) -> Result<Member, RustAuthError> {
        let mut create = Create::new("member")
            .data("id", DbValue::String(generate_random_string(ID_LENGTH)))
            .data(
                "organization_id",
                DbValue::String(organization_id.to_owned()),
            )
            .data("user_id", DbValue::String(user_id.to_owned()))
            .data("role", DbValue::String(role.to_owned()))
            .data("created_at", DbValue::Timestamp(OffsetDateTime::now_utc()))
            .force_allow_id();
        for (field, value) in additional_fields {
            create = create.data(field, value);
        }
        let record = self.adapter.create(create).await?;
        member_from_record(&record)
    }

    pub async fn member_by_org_user(
        &self,
        organization_id: &str,
        user_id: &str,
    ) -> Result<Option<Member>, RustAuthError> {
        self.adapter
            .find_one(
                FindOne::new("member")
                    .where_clause(Where::new(
                        "organization_id",
                        DbValue::String(organization_id.to_owned()),
                    ))
                    .where_clause(Where::new("user_id", DbValue::String(user_id.to_owned()))),
            )
            .await?
            .map(|record| member_from_record(&record))
            .transpose()
    }

    pub async fn member_by_id(&self, id: &str) -> Result<Option<Member>, RustAuthError> {
        self.adapter
            .find_one(FindOne::new("member").where_clause(id_where(id)))
            .await?
            .map(|record| member_from_record(&record))
            .transpose()
    }

    pub async fn member_by_email(
        &self,
        organization_id: &str,
        email: &str,
    ) -> Result<Option<Member>, RustAuthError> {
        let Some(user) = self.user_by_email(email).await? else {
            return Ok(None);
        };
        self.member_by_org_user(organization_id, &user.id).await
    }

    pub async fn members(&self, organization_id: &str) -> Result<Vec<Member>, RustAuthError> {
        self.adapter
            .find_many(
                FindMany::new("member")
                    .where_clause(Where::new(
                        "organization_id",
                        DbValue::String(organization_id.to_owned()),
                    ))
                    .sort_by(Sort::new("created_at", SortDirection::Asc)),
            )
            .await?
            .iter()
            .map(member_from_record)
            .collect()
    }

    pub async fn list_members(&self, query: MemberListQuery) -> Result<Vec<Member>, RustAuthError> {
        let mut find = FindMany::new("member").where_clause(Where::new(
            "organization_id",
            DbValue::String(query.organization_id),
        ));
        for clause in query.filters {
            find = find.where_clause(clause);
        }
        if let Some(limit) = query.limit {
            find = find.limit(limit);
        }
        if let Some(offset) = query.offset {
            find = find.offset(offset);
        }
        find = find.sort_by(query.sort);
        self.adapter
            .find_many(find)
            .await?
            .iter()
            .map(member_from_record)
            .collect()
    }

    pub async fn count_members(&self, organization_id: &str) -> Result<u64, RustAuthError> {
        self.adapter
            .count(Count::new("member").where_clause(Where::new(
                "organization_id",
                DbValue::String(organization_id.to_owned()),
            )))
            .await
    }

    pub async fn count_members_matching(
        &self,
        organization_id: &str,
        filters: Vec<Where>,
    ) -> Result<u64, RustAuthError> {
        let mut count = Count::new("member").where_clause(Where::new(
            "organization_id",
            DbValue::String(organization_id.to_owned()),
        ));
        for clause in filters {
            count = count.where_clause(clause);
        }
        self.adapter.count(count).await
    }

    pub async fn update_member_role(
        &self,
        member_id: &str,
        role: &str,
        additional_fields: DbRecord,
    ) -> Result<Option<Member>, RustAuthError> {
        let mut update = Update::new("member")
            .where_clause(id_where(member_id))
            .data("role", DbValue::String(role.to_owned()));
        for (field, value) in additional_fields {
            update = update.data(field, value);
        }
        self.adapter
            .update(update)
            .await?
            .map(|record| member_from_record(&record))
            .transpose()
    }

    pub async fn delete_member(&self, member_id: &str) -> Result<(), RustAuthError> {
        self.adapter
            .delete(Delete::new("member").where_clause(id_where(member_id)))
            .await
    }

    pub async fn user_by_id(
        &self,
        id: &str,
    ) -> Result<Option<rustauth_core::db::User>, RustAuthError> {
        self.adapter
            .find_one(FindOne::new("user").where_clause(id_where(id)))
            .await?
            .map(|record| user_from_record(&record))
            .transpose()
    }

    pub async fn user_by_email(
        &self,
        email: &str,
    ) -> Result<Option<rustauth_core::db::User>, RustAuthError> {
        self.adapter
            .find_one(
                FindOne::new("user").where_clause(
                    Where::new("email", DbValue::String(email.to_owned())).insensitive(),
                ),
            )
            .await?
            .map(|record| user_from_record(&record))
            .transpose()
    }

    pub async fn organizations_for_user(
        &self,
        user_id: &str,
    ) -> Result<Vec<Organization>, RustAuthError> {
        let members = self
            .adapter
            .find_many(
                FindMany::new("member")
                    .where_clause(Where::new("user_id", DbValue::String(user_id.to_owned()))),
            )
            .await?;
        let mut organizations = Vec::new();
        for member in members {
            let organization_id = required_string(&member, "organization_id")?;
            if let Some(organization) = self.organization_by_id(&organization_id).await? {
                organizations.push(organization);
            }
        }
        Ok(organizations)
    }

    pub async fn create_invitation(
        &self,
        input: CreateInvitationInput<'_>,
    ) -> Result<Invitation, RustAuthError> {
        let mut create = Create::new("invitation")
            .data("id", DbValue::String(generate_random_string(ID_LENGTH)))
            .data(
                "organization_id",
                DbValue::String(input.organization_id.to_owned()),
            )
            .data("email", DbValue::String(input.email.to_owned()))
            .data("role", DbValue::String(input.role.to_owned()))
            .data(
                "team_id",
                input
                    .team_id
                    .map(|value| DbValue::String(value.to_owned()))
                    .unwrap_or(DbValue::Null),
            )
            .data(
                "status",
                DbValue::String(InvitationStatus::Pending.as_str().to_owned()),
            )
            .data("expires_at", DbValue::Timestamp(input.expires_at))
            .data("created_at", DbValue::Timestamp(OffsetDateTime::now_utc()))
            .data("inviter_id", DbValue::String(input.inviter_id.to_owned()))
            .force_allow_id();
        for (field, value) in input.additional_fields {
            create = create.data(field, value);
        }
        let record = self.adapter.create(create).await?;
        invitation_from_record(&record)
    }

    pub async fn invitation_by_id(&self, id: &str) -> Result<Option<Invitation>, RustAuthError> {
        self.adapter
            .find_one(FindOne::new("invitation").where_clause(id_where(id)))
            .await?
            .map(|record| invitation_from_record(&record))
            .transpose()
    }

    pub async fn pending_invitations(
        &self,
        organization_id: &str,
    ) -> Result<Vec<Invitation>, RustAuthError> {
        self.adapter
            .find_many(
                FindMany::new("invitation")
                    .where_clause(Where::new(
                        "organization_id",
                        DbValue::String(organization_id.to_owned()),
                    ))
                    .where_clause(Where::new(
                        "status",
                        DbValue::String(InvitationStatus::Pending.as_str().to_owned()),
                    )),
            )
            .await?
            .iter()
            .map(invitation_from_record)
            .collect()
    }

    pub async fn pending_invitation_by_email(
        &self,
        organization_id: &str,
        email: &str,
    ) -> Result<Option<Invitation>, RustAuthError> {
        self.adapter
            .find_one(
                FindOne::new("invitation")
                    .where_clause(Where::new(
                        "organization_id",
                        DbValue::String(organization_id.to_owned()),
                    ))
                    .where_clause(Where::new("email", DbValue::String(email.to_owned())))
                    .where_clause(Where::new(
                        "status",
                        DbValue::String(InvitationStatus::Pending.as_str().to_owned()),
                    )),
            )
            .await?
            .map(|record| invitation_from_record(&record))
            .transpose()
    }

    pub async fn update_invitation_status(
        &self,
        id: &str,
        status: InvitationStatus,
    ) -> Result<Option<Invitation>, RustAuthError> {
        self.adapter
            .update(
                Update::new("invitation")
                    .where_clause(id_where(id))
                    .data("status", DbValue::String(status.as_str().to_owned())),
            )
            .await?
            .map(|record| invitation_from_record(&record))
            .transpose()
    }

    pub async fn extend_invitation(
        &self,
        id: &str,
        expires_at: OffsetDateTime,
    ) -> Result<Option<Invitation>, RustAuthError> {
        self.adapter
            .update(
                Update::new("invitation")
                    .where_clause(id_where(id))
                    .data("expires_at", DbValue::Timestamp(expires_at)),
            )
            .await?
            .map(|record| invitation_from_record(&record))
            .transpose()
    }

    pub async fn invitations_for_organization(
        &self,
        organization_id: &str,
    ) -> Result<Vec<Invitation>, RustAuthError> {
        self.adapter
            .find_many(FindMany::new("invitation").where_clause(Where::new(
                "organization_id",
                DbValue::String(organization_id.to_owned()),
            )))
            .await?
            .iter()
            .map(invitation_from_record)
            .collect()
    }

    pub async fn invitations_for_email(
        &self,
        email: &str,
    ) -> Result<Vec<Invitation>, RustAuthError> {
        self.adapter
            .find_many(
                FindMany::new("invitation")
                    .where_clause(Where::new("email", DbValue::String(email.to_owned())))
                    .where_clause(Where::new(
                        "status",
                        DbValue::String(InvitationStatus::Pending.as_str().to_owned()),
                    )),
            )
            .await?
            .iter()
            .map(invitation_from_record)
            .collect()
    }
}

#[derive(Debug, Default)]
pub struct OrganizationUpdate {
    pub name: Option<String>,
    pub slug: Option<String>,
    pub logo: Option<String>,
    pub logo_set: bool,
    pub metadata: Option<serde_json::Value>,
    pub metadata_set: bool,
    pub additional_fields: DbRecord,
}

#[derive(Debug, Clone)]
pub struct MemberListQuery {
    pub organization_id: String,
    pub filters: Vec<Where>,
    pub limit: Option<usize>,
    pub offset: Option<usize>,
    pub sort: Sort,
}

impl MemberListQuery {
    pub fn new(organization_id: impl Into<String>) -> Self {
        Self {
            organization_id: organization_id.into(),
            filters: Vec::new(),
            limit: None,
            offset: None,
            sort: Sort::new("created_at", SortDirection::Asc),
        }
    }

    #[must_use]
    pub fn filter(
        mut self,
        field: impl Into<String>,
        value: DbValue,
        operator: WhereOperator,
    ) -> Self {
        self.filters
            .push(Where::new(field, value).operator(operator));
        self
    }

    #[must_use]
    pub fn limit(mut self, limit: usize) -> Self {
        self.limit = Some(limit);
        self
    }

    #[must_use]
    pub fn offset(mut self, offset: usize) -> Self {
        self.offset = Some(offset);
        self
    }

    #[must_use]
    pub fn sort(mut self, field: impl Into<String>, direction: SortDirection) -> Self {
        self.sort = Sort::new(field, direction);
        self
    }
}

pub struct CreateInvitationInput<'a> {
    pub organization_id: &'a str,
    pub email: &'a str,
    pub role: &'a str,
    pub team_id: Option<&'a str>,
    pub inviter_id: &'a str,
    pub expires_at: OffsetDateTime,
    pub additional_fields: DbRecord,
}

pub(super) fn id_where(id: &str) -> Where {
    Where::new("id", DbValue::String(id.to_owned()))
}

pub(super) fn option_string(value: Option<String>) -> DbValue {
    value.map(DbValue::String).unwrap_or(DbValue::Null)
}
