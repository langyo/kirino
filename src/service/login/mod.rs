use std::sync::Arc;

use anyhow::{anyhow, Result};
use chrono::Utc;
use uuid::Uuid;

use crate::auth::credential::basic::JwtManager;
use crate::auth::passport::static_password::{hash_password, verify_password};
use crate::models::identity::Identity;
use crate::rbac::engine::RbacEngine;
use crate::rbac::store::memory::InMemoryAssignmentStore;
use crate::rbac::store::registry::{SimpleRole, StaticPermissionRegistry, StaticRoleRegistry};
use crate::rbac::subject::StringSubject;
use crate::rbac::traits::{AssignmentStore, Permission, Role};

#[derive(Debug, Clone)]
pub struct UserRecord {
    pub id: Uuid,
    pub username: String,
    pub password_hash: String,
    pub display_name: Option<String>,
    pub is_active: bool,
    pub identity: Identity,
    pub created_at: chrono::DateTime<Utc>,
    pub updated_at: chrono::DateTime<Utc>,
}

#[derive(Debug, Clone)]
pub struct LoginResult {
    pub token: String,
    pub user_id: String,
    pub username: String,
    pub display_name: Option<String>,
    pub roles: Vec<String>,
}

pub struct AuthService<DB, P, R, A>
where
    P: Permission,
    R: Role<P>,
    A: AssignmentStore<StringSubject, P>,
{
    db: DB,
    jwt: JwtManager,
    engine: Arc<RbacEngine<StringSubject, P, R, A>>,
    first_user_role: String,
    default_role: String,
}

impl<DB, P, R, A> AuthService<DB, P, R, A>
where
    DB: UserDatabase,
    P: Permission,
    R: Role<P>,
    A: AssignmentStore<StringSubject, P>,
{
    pub fn new(
        db: DB,
        jwt_secret: &str,
        jwt_expiration_hours: i64,
        engine: Arc<RbacEngine<StringSubject, P, R, A>>,
        first_user_role: &str,
        default_role: &str,
    ) -> Self {
        Self {
            db,
            jwt: JwtManager::new(jwt_secret, jwt_expiration_hours),
            engine,
            first_user_role: first_user_role.to_string(),
            default_role: default_role.to_string(),
        }
    }

    pub fn jwt_manager(&self) -> &JwtManager {
        &self.jwt
    }

    pub fn engine(&self) -> &Arc<RbacEngine<StringSubject, P, R, A>> {
        &self.engine
    }

    pub async fn register(
        &self,
        username: &str,
        password: &str,
        display_name: Option<&str>,
    ) -> Result<UserRecord> {
        if username.trim().is_empty() {
            return Err(anyhow!("username must not be empty"));
        }
        if password.len() < 6 {
            return Err(anyhow!("password must be at least 6 characters"));
        }

        if self.db.find_by_username(username).await?.is_some() {
            return Err(anyhow!("username already exists"));
        }

        let password_hash = hash_password(password)?;
        let user_id = Uuid::now_v7();
        let now = Utc::now();
        let identity = Identity::Basic { id: user_id };

        let user = UserRecord {
            id: user_id,
            username: username.to_string(),
            password_hash,
            display_name: display_name.map(|s| s.to_string()),
            is_active: true,
            identity,
            created_at: now,
            updated_at: now,
        };

        self.db.create_user(&user).await?;

        let is_first = self.db.count_users().await? <= 1;
        let role_name = if is_first {
            &self.first_user_role
        } else {
            &self.default_role
        };

        let subject = StringSubject::new(user_id.to_string());
        self.engine
            .assignment_store()
            .assign_role(&subject, role_name)
            .await?;

        Ok(user)
    }

    pub async fn login(&self, username: &str, password: &str) -> Result<LoginResult> {
        let user = self
            .db
            .find_by_username(username)
            .await?
            .ok_or_else(|| anyhow!("invalid credentials"))?;

        if !user.is_active {
            return Err(anyhow!("account disabled"));
        }

        if !verify_password(password, &user.password_hash)? {
            return Err(anyhow!("invalid credentials"));
        }

        let user_id = user.id.to_string();
        let subject = StringSubject::new(&user_id);
        let roles = self
            .engine
            .assignment_store()
            .roles_of(&subject)
            .await
            .unwrap_or_default();

        let token = self.jwt.issue(&user_id, &user.username, roles.clone())?;

        Ok(LoginResult {
            token,
            user_id,
            username: user.username.clone(),
            display_name: user.display_name.clone(),
            roles,
        })
    }

    pub async fn verify_token(
        &self,
        token: &str,
    ) -> Result<crate::auth::credential::basic::Claims> {
        self.jwt.verify(token)
    }

    pub async fn check_permission(&self, user_id: &str, permission: &P) -> bool {
        let subject = StringSubject::new(user_id);
        self.engine.check(&subject, permission).await
    }

    pub async fn change_password(
        &self,
        user_id: &str,
        old_password: &str,
        new_password: &str,
    ) -> Result<()> {
        let uid = Uuid::parse_str(user_id).map_err(|_| anyhow!("invalid user_id"))?;

        let user = self
            .db
            .find_by_id(&uid)
            .await?
            .ok_or_else(|| anyhow!("user not found"))?;

        if !verify_password(old_password, &user.password_hash)? {
            return Err(anyhow!("old password is incorrect"));
        }

        if new_password.len() < 6 {
            return Err(anyhow!("new password must be at least 6 characters"));
        }

        let new_hash = hash_password(new_password)?;
        self.db.update_password(&uid, &new_hash).await
    }

    pub async fn list_users(&self) -> Result<Vec<UserRecord>> {
        self.db.list_users().await
    }

    pub async fn delete_user(&self, user_id: &str) -> Result<bool> {
        let uid = Uuid::parse_str(user_id).map_err(|_| anyhow!("invalid user_id"))?;
        self.db.delete_user(&uid).await
    }
}

pub fn build_compat_engine() -> Arc<
    RbacEngine<
        StringSubject,
        crate::rbac::compat::Permission,
        SimpleRole<crate::rbac::compat::Permission>,
        InMemoryAssignmentStore<StringSubject, crate::rbac::compat::Permission>,
    >,
> {
    use crate::rbac::compat::Permission;

    let mut role_reg = StaticRoleRegistry::new();
    role_reg.register(SimpleRole::new("admin", Permission::all()));
    role_reg.register(SimpleRole::new(
        "operator",
        [
            Permission::AgentRead,
            Permission::AgentWrite,
            Permission::AgentExecute,
            Permission::ConfigRead,
            Permission::ConfigWrite,
            Permission::KnowledgeRead,
            Permission::KnowledgeWrite,
            Permission::ContainerRead,
            Permission::ContainerWrite,
            Permission::DeployRead,
            Permission::DeployExecute,
            Permission::SystemRead,
        ]
        .iter()
        .copied()
        .collect(),
    ));
    role_reg.register(SimpleRole::new(
        "viewer",
        [
            Permission::AgentRead,
            Permission::ConfigRead,
            Permission::KnowledgeRead,
            Permission::ContainerRead,
            Permission::SystemRead,
            Permission::DeployRead,
        ]
        .iter()
        .copied()
        .collect(),
    ));
    role_reg.register(SimpleRole::new(
        "agent",
        [
            Permission::AgentRead,
            Permission::AgentExecute,
            Permission::KnowledgeRead,
        ]
        .iter()
        .copied()
        .collect(),
    ));

    let perm_reg = StaticPermissionRegistry::new(Permission::all());
    let store = InMemoryAssignmentStore::new();

    Arc::new(RbacEngine::new(
        Arc::new(role_reg),
        Arc::new(perm_reg),
        Arc::new(store),
    ))
}

#[async_trait::async_trait]
pub trait UserDatabase: Send + Sync + Clone + 'static {
    async fn create_user(&self, user: &UserRecord) -> Result<()>;
    async fn find_by_username(&self, username: &str) -> Result<Option<UserRecord>>;
    async fn find_by_id(&self, id: &Uuid) -> Result<Option<UserRecord>>;
    async fn update_password(&self, id: &Uuid, new_hash: &str) -> Result<()>;
    async fn delete_user(&self, id: &Uuid) -> Result<bool>;
    async fn list_users(&self) -> Result<Vec<UserRecord>>;
    async fn count_users(&self) -> Result<u64>;
}
