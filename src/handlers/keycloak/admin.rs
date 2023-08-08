use std::env::var;
use actix_web::HttpResponse;
use actix_web_httpauth::extractors::bearer::BearerAuth;
use keycloak::types::{
    RealmRepresentation,
};
use keycloak::{KeycloakAdmin, KeycloakAdminToken};
use log::info;

pub(crate) fn get_keycloak_admin(token: &str) -> KeycloakAdmin {
    let url = var("KEYCLOAK_ADDR").unwrap();
    let dummy_token_response = format!(
        "{{
            \"access_token\": \"{token}\",
            \"expires_in\": 60,
            \"scope\": \"email phone\",
            \"token_type\": \"Bearer\"
        }}"
    );
    let admin_token: KeycloakAdminToken =
        serde_json::from_str(dummy_token_response.as_str()).unwrap();
    KeycloakAdmin::new(&url, admin_token, reqwest::Client::new())
}

pub async fn seed(auth: BearerAuth) -> HttpResponse {
    let admin = get_keycloak_admin(auth.token());
    admin
        .post(RealmRepresentation {
            realm: Some(var("REALM").unwrap()),
            enabled: Some(true),
            reset_password_allowed: Some(true),
            offline_session_idle_timeout: Some(30 * 60), // 30 minutes to secs
            ..Default::default()
        })
        .await
        .unwrap_or_else(|x| info!("Unable to create realm: {x}"));

    HttpResponse::Ok().finish()
}
