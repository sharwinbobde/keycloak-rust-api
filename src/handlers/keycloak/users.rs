use actix_web::HttpResponse;
use actix_web_httpauth::extractors::bearer::BearerAuth;
use dotenv::var;
use keycloak::types::*;
use log::error;
use regex::Regex;
use serde::{Deserialize, Serialize};
use validator::{Validate, ValidationError};

use crate::handlers::keycloak::admin::{get_keycloak_admin};

pub async fn get_users(auth: BearerAuth) -> HttpResponse {
    let admin = get_keycloak_admin(auth.token());
    match admin
        .realm_users_get(
            var("REALM").unwrap().as_str(),
            None, None, None, None, None, None, None, None, None, None, None, None, None,
            None,
        )
        .await
    {
        Ok(users) => HttpResponse::Ok().json(users),
        Err(e) => {
            return HttpResponse::InternalServerError()
                .body(format!("Unable to get clients: {:?}", e))
        }
    }
}

#[derive(Debug, Serialize, Deserialize, Validate)]
pub struct User {
    #[validate(length(min = 8, max = 30), custom = "validate_username")]
    username: String,
    #[validate(email)]
    email: String,
}
fn validate_username(username: &str) -> Result<(), ValidationError> {
    const USERNAME_REGEX: &str = "^[a-zA-Z0-9_-]{10,200}$";
    let re = Regex::new(USERNAME_REGEX.clone()).unwrap();
    match re.is_match(username) {
        true => Ok(()),
        false => Err(ValidationError::new("username does not match regex")),
    }
}
pub async fn post_user(auth: BearerAuth, user: actix_web::web::Json<User>) -> HttpResponse {
    match user.validate() {
        Err(e) => HttpResponse::BadRequest().body(format!("Validation Error: {:?}", e)),

        Ok(_) => {
            let admin = get_keycloak_admin(auth.token());
            match admin
                .realm_users_post(
                    var("REALM").unwrap().as_str(),
                    UserRepresentation {
                        enabled: Some(true),
                        username: Some(user.username.clone()),
                        email: Some(user.email.clone()),

                        ..Default::default()
                    },
                )
                .await
            {
                Err(e) => {
                    error!("Unable to create user: {:?}", e);
                    HttpResponse::InternalServerError()
                        .body(format!("Unable to create user: {:?}", e))
                },

                _ => HttpResponse::Ok().finish(),
            }
        }
    }
}
#[derive(Debug, Serialize, Deserialize, Validate, Clone)]
pub struct UserPassword {
    #[validate(length(min = 8, max = 30), custom = "validate_username")]
    username: String,
    #[validate(email)]
    email: String,
    #[validate(length(min = 10, max = 200))]
    password: String,
}
pub async fn reset_password(
    auth: BearerAuth,
    user_password: actix_web::web::Json<UserPassword>,
) -> HttpResponse {
    match user_password.validate() {
        Err(e) => HttpResponse::BadRequest().body(format!("Validation Error: {:?}", e)),

        Ok(_) => {
            let admin = get_keycloak_admin(auth.token());
            let user_id = match admin
                .realm_users_get(
                    var("REALM").unwrap().as_str(),
                    None,
                    Some(user_password.clone().email),
                    None,
                    None,
                    None,
                    None,
                    None,
                    None,
                    None,
                    None,
                    None,
                    None,
                    None,
                    Some(user_password.clone().username),
                )
                .await
            {
                Ok(users) => {
                    // users is a set of users that contain the username and email, but this can be a substring
                    let mut user_id: String = "".to_string();
                    for user in users {
                        if user.username.unwrap() == user_password.username.clone() {
                            user_id = user.id.unwrap();
                        }
                    }
                    if user_id.as_str() == "" {
                        return HttpResponse::NoContent().finish(); // returns code 204
                    }
                    user_id
                }
                Err(e) => {
                    return HttpResponse::InternalServerError()
                        .body(format!("Unable to get clients: {:?}", e))
                }
            };
            match admin
                .realm_users_with_id_reset_password_put(
                    var("REALM").unwrap().as_str(),
                    user_id.as_str(),
                    CredentialRepresentation {
                        temporary: Some(false),
                        value: Some(user_password.password.clone()),
                        ..Default::default()
                    },
                )
                .await
            {
                Err(e) => HttpResponse::InternalServerError()
                    .body(format!("Unable to reset password: {:?}", e)),

                _ => HttpResponse::Ok().finish(),
            }
        }
    }
}
