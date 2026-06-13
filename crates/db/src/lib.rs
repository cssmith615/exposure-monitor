use ceem_shared::{
    MemberRole, Organization, OrganizationMember, OrganizationMembership, UserAccount,
};
use serde::{Deserialize, Serialize};
use sqlx::{PgPool, Row, postgres::PgPoolOptions};
use uuid::Uuid;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct DatabaseConfig {
    pub url: String,
}

impl DatabaseConfig {
    pub fn from_env() -> Result<Self, std::env::VarError> {
        Ok(Self {
            url: std::env::var("DATABASE_URL")?,
        })
    }
}

#[derive(Debug, Clone)]
pub struct PostgresRepository {
    pool: PgPool,
}

impl PostgresRepository {
    pub async fn connect(config: &DatabaseConfig) -> Result<Self, sqlx::Error> {
        let pool = PgPoolOptions::new()
            .max_connections(8)
            .connect(&config.url)
            .await?;

        Ok(Self { pool })
    }

    pub fn from_pool(pool: PgPool) -> Self {
        Self { pool }
    }

    pub fn pool(&self) -> &PgPool {
        &self.pool
    }

    pub async fn migrate(&self) -> Result<(), sqlx::migrate::MigrateError> {
        sqlx::migrate!("../../migrations").run(&self.pool).await
    }

    pub async fn create_user(
        &self,
        email: &str,
        display_name: &str,
        password_hash: &str,
    ) -> Result<UserAccount, sqlx::Error> {
        let id = Uuid::now_v7();
        let row = sqlx::query(
            r#"
            INSERT INTO users (id, email, display_name, password_hash)
            VALUES ($1, $2, $3, $4)
            RETURNING id, email, display_name, email_verified_at, created_at
            "#,
        )
        .bind(id)
        .bind(email)
        .bind(display_name)
        .bind(password_hash)
        .fetch_one(&self.pool)
        .await?;

        Ok(user_from_row(&row))
    }

    pub async fn find_user_by_email(
        &self,
        email: &str,
    ) -> Result<Option<(UserAccount, String)>, sqlx::Error> {
        let row = sqlx::query(
            r#"
            SELECT id, email, display_name, email_verified_at, password_hash, created_at
            FROM users
            WHERE email = $1
            "#,
        )
        .bind(email)
        .fetch_optional(&self.pool)
        .await?;

        Ok(row.map(|row| (user_from_row(&row), row.get("password_hash"))))
    }

    pub async fn create_organization_with_owner(
        &self,
        owner_user_id: Uuid,
        name: &str,
        slug: &str,
    ) -> Result<(Organization, OrganizationMembership), sqlx::Error> {
        let mut transaction = self.pool.begin().await?;
        let organization_id = Uuid::now_v7();
        let organization_row = sqlx::query(
            r#"
            INSERT INTO organizations (id, name, slug)
            VALUES ($1, $2, $3)
            RETURNING id, name, slug, created_at
            "#,
        )
        .bind(organization_id)
        .bind(name)
        .bind(slug)
        .fetch_one(&mut *transaction)
        .await?;
        let membership_row = sqlx::query(
            r#"
            INSERT INTO organization_members (organization_id, user_id, role)
            VALUES ($1, $2, $3::member_role)
            RETURNING organization_id, user_id, role::text AS role, created_at
            "#,
        )
        .bind(organization_id)
        .bind(owner_user_id)
        .bind(member_role_as_str(MemberRole::Owner))
        .fetch_one(&mut *transaction)
        .await?;
        transaction.commit().await?;

        Ok((
            organization_from_row(&organization_row),
            membership_from_row(&membership_row),
        ))
    }

    pub async fn list_organization_members(
        &self,
        organization_id: Uuid,
    ) -> Result<Vec<OrganizationMember>, sqlx::Error> {
        let rows = sqlx::query(
            r#"
            SELECT
                users.id,
                users.email,
                users.display_name,
                users.email_verified_at,
                users.created_at AS user_created_at,
                organization_members.role::text AS role,
                organization_members.created_at AS membership_created_at
            FROM organization_members
            INNER JOIN users ON users.id = organization_members.user_id
            WHERE organization_members.organization_id = $1
            ORDER BY users.email ASC
            "#,
        )
        .bind(organization_id)
        .fetch_all(&self.pool)
        .await?;

        Ok(rows
            .iter()
            .map(|row| OrganizationMember {
                user: UserAccount {
                    id: row.get("id"),
                    email: row.get("email"),
                    display_name: row.get("display_name"),
                    email_verified_at: row.get("email_verified_at"),
                    created_at: row.get("user_created_at"),
                },
                role: parse_member_role(row.get::<&str, _>("role")),
                created_at: row.get("membership_created_at"),
            })
            .collect())
    }
}

fn user_from_row(row: &sqlx::postgres::PgRow) -> UserAccount {
    UserAccount {
        id: row.get("id"),
        email: row.get("email"),
        display_name: row.get("display_name"),
        email_verified_at: row.get("email_verified_at"),
        created_at: row.get("created_at"),
    }
}

fn organization_from_row(row: &sqlx::postgres::PgRow) -> Organization {
    Organization {
        id: row.get("id"),
        name: row.get("name"),
        slug: row.get("slug"),
        created_at: row.get("created_at"),
    }
}

fn membership_from_row(row: &sqlx::postgres::PgRow) -> OrganizationMembership {
    OrganizationMembership {
        organization_id: row.get("organization_id"),
        user_id: row.get("user_id"),
        role: parse_member_role(row.get::<&str, _>("role")),
        created_at: row.get("created_at"),
    }
}

pub fn member_role_as_str(role: MemberRole) -> &'static str {
    match role {
        MemberRole::Owner => "owner",
        MemberRole::Admin => "admin",
        MemberRole::Member => "member",
        MemberRole::Viewer => "viewer",
    }
}

pub fn parse_member_role(value: &str) -> MemberRole {
    match value {
        "owner" => MemberRole::Owner,
        "admin" => MemberRole::Admin,
        "member" => MemberRole::Member,
        "viewer" => MemberRole::Viewer,
        _ => MemberRole::Viewer,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn stores_database_url() {
        let config = DatabaseConfig {
            url: "postgres://ceem:ceem@localhost:5432/ceem".to_string(),
        };

        assert!(config.url.contains("postgres://"));
    }

    #[test]
    fn maps_member_roles_to_database_values() {
        assert_eq!(member_role_as_str(MemberRole::Owner), "owner");
        assert_eq!(parse_member_role("admin"), MemberRole::Admin);
        assert_eq!(parse_member_role("unknown"), MemberRole::Viewer);
    }

    #[tokio::test]
    async fn creates_user_organization_and_membership_when_database_is_available() {
        let Ok(config) = DatabaseConfig::from_env() else {
            return;
        };
        let repository = match PostgresRepository::connect(&config).await {
            Ok(repository) => repository,
            Err(_) => return,
        };
        repository.migrate().await.unwrap();
        let suffix = Uuid::now_v7();
        let email = format!("repo-test-{suffix}@example.com");
        let slug = format!("repo-{suffix}");
        let user = repository
            .create_user(&email, "Repo Test", "$argon2id$placeholder")
            .await
            .unwrap();
        let (organization, membership) = repository
            .create_organization_with_owner(user.id, "Repo Test Org", &slug)
            .await
            .unwrap();
        let members = repository
            .list_organization_members(organization.id)
            .await
            .unwrap();

        assert_eq!(membership.role, MemberRole::Owner);
        assert_eq!(members.len(), 1);
        assert_eq!(members[0].user.email, email);
    }
}
