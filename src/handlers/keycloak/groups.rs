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
pub struct GroupParams {
    #[validate(length(min = 5, max = 100))]
    group_name: String,
}
pub async fn post_group(
    auth: BearerAuth,
    params: actix_web::web::Json<GroupParams>,
) -> HttpResponse {
    match params.validate() {
        Err(e) => HttpResponse::BadRequest().body(format!("Validation Error: {:?}", e)),
        Ok(_) => {
            let admin = get_keycloak_admin(auth.token());
            match admin.realm_groups_post(
                    var("REALM").unwrap().as_str(),
                    GroupRepresentation {
                        name: Some(params.clone().group_name.into()),
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

#[derive(Deserialize, Serialize, Validate, Clone)]
pub struct GroupAttributesParams {
    #[validate(length(min = 5, max = 100))]
    group_name: String,
    attributes: HashMap<String, Value>
}
pub async fn put_group_attributes(
    auth: BearerAuth,
    params: actix_web::web::Json<GroupAttributesParams>,
) -> HttpResponse {
    match params.validate() {
        Err(e) => HttpResponse::BadRequest().body(format!("Validation Error: {:?}", e)),
        Ok(_) => {
            let admin = get_keycloak_admin(auth.token());

            let matched = admin.realm_groups_get(
                var("REALM").unwrap().as_str(),Some(false),
                Some(true), None, None, None,
                Some(params.group_name.clone())).await
                .unwrap();

            if matched.len() != 1 {
                return HttpResponse::BadRequest().body(format!("Group not found"))
            }

            let id = matched[0].id.clone().unwrap();
            let mut new_entity = matched[0].clone();
            new_entity.attributes = Some(params.attributes.clone());

            match admin.realm_groups_with_id_put(
                var("REALM").unwrap().as_str(),
                id.as_str(),
                new_entity,
            )
                .await {
                Err(e) => HttpResponse::InternalServerError()
                    .body(format!("Error {:?}", e)),

                Ok(_) => HttpResponse::Ok().finish()
            }
        }
    }
}
