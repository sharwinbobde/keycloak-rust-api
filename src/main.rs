mod handlers;
use actix_web_middleware_keycloak_auth::{AlwaysReturnPolicy, DecodingKey, KeycloakAuth};
extern crate core;
extern crate jsonwebkey as jwk;

use actix_web::{
    middleware::Logger,
    web::{get, patch, post, put, resource, scope},
    App, HttpServer,
};

use crate::handlers::keycloak::admin::seed_realm;
use crate::handlers::keycloak::clients::{get_clients, post_client};
use crate::handlers::keycloak::users::{get_users, post_user};
use dotenv::{dotenv, var};
use log::info;
use crate::handlers::keycloak::groups::{get_groups, post_group};

#[actix_rt::main]
async fn main() -> std::io::Result<()> {
    // get values from .env
    dotenv().ok();
    std::env::set_var("RUST_BACKTRACE", "1");
    std::env::set_var("RUST_LOG", "warn");
    std::env::set_var("RUST_LOG", "actix_web=warn,actix_server=warn");
    simple_logger::init_with_level(log::Level::Info).unwrap();

    let url = std::env::var("KEYCLOAK_ADDR").unwrap();
    info!("KEYCLOAK_ADDR={url}");
    let realm = var("REALM").unwrap();
    info!("REALM={realm}");
    let certs = reqwest::get(format!("{url}/realms/master/protocol/openid-connect/certs"))
        .await
        .expect("cannot connect to Keycloak")
        .json::<serde_json::Value>()
        .await
        .expect("cannot jsonify the Keycloak JWK json");
    let jwt: String;
    match certs["keys"].clone().as_array() {
        Some(cert_keys) => {
            if cert_keys.len() != 2 {
                panic!("Num of certs is greater than 2")
            }
            if cert_keys[0]["alg"] == "RS256" {
                jwt = cert_keys[0].to_string();
            } else {
                jwt = cert_keys[1].to_string();
            }
        }
        None => panic!("certs is not an array"),
    }
    let the_jwk: jwk::JsonWebKey = jwt.parse().unwrap();
    let jwk_pem = the_jwk.key.to_pem();

    // start api workers
    let workers = var("WORKERS_AMOUNT")
        .unwrap_or_else(|_| "24".to_string())
        .parse()
        .unwrap_or(24);
    HttpServer::new(move || {
        let keycloak_auth_user = KeycloakAuth {
            detailed_responses: true,
            passthrough_policy: AlwaysReturnPolicy,
            keycloak_oid_public_key: DecodingKey::from_rsa_pem(jwk_pem.as_bytes()).unwrap(),
            required_roles: vec![],
        };
        App::new()
            .wrap(Logger::default())
            .service(resource("/").route(get().to(handlers::health::get)))
            .service(
                scope("/admin")
                    .wrap(keycloak_auth_user)
                    .service(resource("/").route(get().to(handlers::health::get)))
                    .service(resource("seed").route(patch().to(seed_realm)))
                    .service(
                        resource("clients")
                            .route(get().to(get_clients))
                            .route(post().to(post_client)),
                    )
                    .service(
                        resource("users")
                            .route(get().to(get_users))
                            .route(post().to(post_user)),
                    )
                    .service(
                        resource("groups")
                            .route(get().to(get_groups))
                            .route(post().to(post_group)),
                    )
                    .service(
                        resource("users/reset-password")
                            .route(put().to(handlers::keycloak::users::reset_password)),
                    ),
            )
    })
    .workers(workers)
    .bind("0.0.0.0:9480")?
    .run()
    .await
}
