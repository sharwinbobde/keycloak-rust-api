use std::collections::HashMap;
use actix_web::HttpResponse;
use actix_web_httpauth::extractors::bearer::BearerAuth;
use dotenv::var;
use keycloak::types::*;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use validator::Validate;

use crate::handlers::keycloak::admin::{get_keycloak_admin};

pub async fn get_groups(auth: BearerAuth) -> HttpResponse {
    let admin = get_keycloak_admin(auth.token());

    match admin.realm_groups_get(var("REALM").unwrap().as_str(),
                           Some(false), Some(true), None, None, None, None)
        .await {
        Ok(clients) => HttpResponse::Ok().json(clients),
        Err(e) => {
            return HttpResponse::InternalServerError()
                .body(format!("Unable to get clients: {:?}", e))
        }
    }
}

#[derive(Deserialize, Serialize)]
struct GroupCreatedResponse {
    status: String,
    message: String,
}

#[derive(Deserialize, Serialize, Validate, Clone)]
pub struct GoupParams {
    #[validate(length(min = 5, max = 100))]
    group_name: String,
}
pub async fn post_group(
    auth: BearerAuth,
    params: actix_web::web::Json<GoupParams>,
) -> HttpResponse {
    match params.validate() {
        Err(e) => HttpResponse::BadRequest().body(format!("Validation Error: {:?}", e)),
        Ok(_) => {
            let admin = get_keycloak_admin(auth.token());
            let mut group_attributes = HashMap::<String, Value>::new();
            group_attributes.insert("some attribute".into(), serde_json::from_str("[\"some value\"]").unwrap());
            match admin.realm_groups_post(
                    var("REALM").unwrap().as_str(),
                    GroupRepresentation {
                        // id: Some(params.clone().group_id.into()),
                        name: Some(params.clone().group_name.into()),
                        attributes: Some(group_attributes),

                        ..Default::default()
                    },
                )
                .await {
                Err(e) => {
                    HttpResponse::InternalServerError().body(format!("Unable to create: {:?}", e))
                }
                Ok(_) => HttpResponse::Ok().json(GroupCreatedResponse {
                    status: "success".into(),
                    message: format!("Group created")
                })
            }
        }
    }
}
