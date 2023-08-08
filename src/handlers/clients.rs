use actix_web::HttpResponse;
use actix_web_httpauth::extractors::bearer::BearerAuth;
use dotenv::var;
use keycloak::types::*;
use serde::{Deserialize, Serialize};
use validator::Validate;

use crate::handlers::admin::{get_keycloak_admin};

pub async fn get_clients(auth: BearerAuth) -> HttpResponse {
    let admin = get_keycloak_admin(auth.token());

    match admin
        .realm_clients_get(var("REALM").unwrap().as_str(),
                           None, None, None, None, None, Some(false))
        .await
    {
        Ok(clients) => HttpResponse::Ok().json(clients),
        Err(e) => {
            return HttpResponse::InternalServerError()
                .body(format!("Unable to get clients: {:?}", e))
        }
    }
}

#[derive(Deserialize, Serialize)]
struct ClientCreatedResponse{
    status: String,
    message: String,
}

#[derive(Deserialize, Serialize, Validate, Clone)]
pub struct ClientParams{
    #[validate(length(min = 5, max = 100))]
    client_id: String,
    #[validate(length(min = 5, max = 100))]
    client_name: String,
    #[validate(length(min = 20, max = 200))]
    client_secret: String,

    #[validate(url)]
    redirect_uri: String,
}
pub async fn post_client(
    auth: BearerAuth,
    client_params: actix_web::web::Json<ClientParams>,
) -> HttpResponse {
    match client_params.validate() {
        Err(e) => HttpResponse::BadRequest().body(format!("Validation Error: {:?}", e)),
        Ok(_) => {
            let admin = get_keycloak_admin(auth.token());
            match admin
                .realm_clients_post(
                    var("REALM").unwrap().as_str(),
                    ClientRepresentation {
                        client_id: Some(client_params.clone().client_id.into()),
                        description: Some("created via \"keycloak-api\" service".into()),
                        // id: Some(CLIENT_ID_2.into()),
                        name: Some(client_params.clone().client_name.into()),
                        secret: Some(client_params.client_secret.clone().into()),
                        redirect_uris: Some(vec![format!("{}/*", client_params.redirect_uri)]),
                        service_accounts_enabled: Some(true),
                        ..Default::default()
                    },
                )
                .await
            {
                Err(e) => {
                    HttpResponse::InternalServerError().body(format!("Unable to create client: {:?}", e))
                }
                Ok(_) => HttpResponse::Ok().json(ClientCreatedResponse{
                    status: "success".into(),
                    message: format!("Client created")
                })
            }
        }
    }
}
