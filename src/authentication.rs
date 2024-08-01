//! Code for user authentication
use actix_session::Session;
use actix_web::cookie::Key;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct Credentials {
    pub username: String,
    pub password: String,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct Account {
    pub credentials: Credentials,
    pub user_id: Uuid,
}

/// Extracts the ID of the signed-in account from a session
pub fn get_account_id(session: Session) -> Uuid {
    session
        .get::<Uuid>("account_uuid")
        .unwrap()
        .expect("Extracting UUID failed.")
}

/// Checks if a session is authorized (signed in)
pub fn check_session(session: Session) -> bool {
    session.get::<bool>("authorized").unwrap().is_some()
}

/// Checks if a provided set of credentials are valid.
/// Returns the matched account if valid, and an error message otherwise.
pub fn check_credentials(
    credentials: Credentials,
    accounts: Vec<Account>,
) -> Result<Account, String> {
    for account in accounts {
        if account.credentials.username == credentials.username
            && argon2::verify_encoded(
                &account.credentials.password,
                credentials.password.as_bytes(),
            )
            .is_ok()
        {
            return Ok(account);
        }
    }
    Err("No account found with the provided credentials".to_string())
}

pub fn get_secret_key() -> Key {
    Key::generate()
}
