use actix_session::storage::CookieSessionStore;
use actix_web::{App, get, HttpRequest, HttpResponse, HttpServer, Responder, web};
use actix_web::cookie::{Cookie};
use actix_web::http::header::HeaderValue;


use actix_web::middleware::Logger;
use anyhow::anyhow;
use handlebars::{Handlebars};
use log::{debug, warn};
use oauth2::{AuthorizationCode, AuthUrl, ClientId, ClientSecret, CsrfToken, PkceCodeChallenge, RedirectUrl, TokenResponse, TokenUrl};
use oauth2::basic::{BasicClient};
use reqwest::{Error, Response};
use reqwest::header::HeaderMap;

use serde::Deserialize;
use serde_json::json;

struct AppState {
    handlebars: Handlebars<'static>,
    oauth2: BasicClient,
}


#[get("/logout")]
async fn logout(data: web::Data<AppState>) -> impl Responder {
    let cookie = Cookie::build("access_token", "")
        .path("/")
        .secure(true)
        .http_only(true)
        .finish();

    HttpResponse::Found()
        .cookie(cookie)
        .append_header(("Location", "/"))
        .finish()
}

#[get("/login/github")]
async fn github_login(data: web::Data<AppState>) -> impl Responder {
    use oauth2::Scope;
    let oauth2 = &data.oauth2;
    let (pkce_challenge, _pkce_verifier) = PkceCodeChallenge::new_random_sha256();

    let (auth_url, _csrf_token) = oauth2
        .authorize_url(CsrfToken::new_random)
        .add_scope(Scope::new("read".to_string()))
        .add_scope(Scope::new("write".to_string()))
        .set_pkce_challenge(pkce_challenge)
        .url();

    debug!("Auth_url: {}", auth_url.as_str());

    HttpResponse::Found()
        .append_header(("Location", auth_url.as_str()))
        .finish()
}


#[derive(Deserialize)]
struct AuthCode {
    code: String,
}

#[get("/auth/github")]
async fn github_redirect(data: web::Data<AppState>, query: web::Query<AuthCode>) -> impl Responder {
    use oauth2::reqwest::async_http_client;
    debug!("Auth code: {}", query.code);

    let oauth2 = &data.oauth2;
    let token = oauth2
        .exchange_code(AuthorizationCode::new(query.code.clone()))
        //.set_pkce_verifier(pkce_verifier)
        .request_async(async_http_client)
        .await;


    match token {
        Ok(token) => {
            debug!("Token: {:?}", token.access_token().secret());
            let cookie = Cookie::build("access_token", token.access_token().secret())
                .path("/")
                .secure(true)
                .http_only(true)
                .finish();

            HttpResponse::Found()
                .cookie(cookie)
                .append_header(("Location", "/"))
                .finish()
        }
        Err(err) => {
            HttpResponse::Unauthorized()
                .body(err.to_string())
        }
    }
}


async fn get_username(access_token: &str) -> Result<String, anyhow::Error> {
    let github_api_url = "https://api.github.com/user";
    let client = reqwest::Client::new();

    let bearer = format!("Bearer {}", access_token);

    let response = client
        .get("https://api.github.com/user")
        .header("user-agent", "actix-web-oauth2-example")
        .header("Accept", "application/vnd.github+json")
        .header("Authorization", bearer.clone())
        .header("X-GitHub-Api-Version", "2022-11-28")
        .send()
        .await?;

    let curl = format!(r#"
    curl -L \
        -H "Accept: application/vnd.github+json" \
        -H "Authorization: {bearer}" \
        -H "X-GitHub-Api-Version: 2022-11-28" \
        https://api.github.com/user
    "#);
    debug!("{}", curl);

    debug!("Github response: {} {response:?}", response.status());

    let user_data = response.json::<serde_json::Value>().await?;
    let username = user_data.get("login").ok_or(anyhow!("Could not retrieve login attribute!"))?.to_string();
    Ok(username)
}

#[get("/")]
async fn index(req: HttpRequest, data: web::Data<AppState>) -> impl Responder {
    let default_context = json!({
        "logged_in":  false,
        "username": null,
    });
    let context =
        if let Some(cookie) = req.cookie("access_token") {
            let access_token = cookie.value();
            let username = get_username(access_token).await;

            match username {
                Ok(username) => {
                    json!({
                        "logged_in":  true,
                        "username": username,
                    })
                }
                Err(err) => {
                    warn!("Error while retrieving username!");
                    default_context
                }
            }
        } else {
            default_context
        };

    let body = data.handlebars.render("index", &context);

    match body {
        Ok(body) => {
            HttpResponse::Ok().body(body)
        }
        Err(err) => {
            HttpResponse::InternalServerError().body(err.to_string())
        }
    }
}

#[get("/css/bulma.min.css")]
async fn bulma() -> impl Responder {
    HttpResponse::Ok()
        .content_type("text/css") // Setze den Content-Type auf "text/css"
        .body(web::Bytes::from_static(include_bytes!("../static/css/bulma.min.css")))
}


fn oauth2_client() -> Result<BasicClient, url::ParseError> {
    Ok(BasicClient::new(
        ClientId::new("7adc7fd9713d21632430".to_string()),
        Some(ClientSecret::new("9158e79f814e20b708b309e85ca2fa59dc3623d3".to_string())),
        AuthUrl::new("https://github.com/login/oauth/authorize".to_string())?,
        Some(TokenUrl::new("https://github.com/login/oauth/access_token".to_string())?),
    ).set_redirect_uri(RedirectUrl::new("https://rocket-oauth2-example.magierdinge.de/auth/github".to_string())?))
}


fn session_middleware() -> actix_session::SessionMiddleware<CookieSessionStore> {
    use actix_session::SessionMiddleware;
    use actix_session::storage::CookieSessionStore;
    use actix_web;
    use actix_web::cookie::Key;
    SessionMiddleware::builder(
        CookieSessionStore::default(), Key::from(&[0; 64]),
    )
        .build()
}

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    stderrlog::new()
        .module(module_path!())
        .module("reqwest")
        .verbosity(log::Level::Trace)
        .timestamp(stderrlog::Timestamp::Millisecond)
        .init().expect("Could not setup logging!");

    let mut handlebars: Handlebars = Handlebars::new();
    handlebars.register_template_string("index", include_str!("../templates/index.html.hbs"))
        .expect("Could not load template \"index\"!");

    let oauth2 = oauth2_client().expect("Could not load OAuth2 Configuration");
    let app_state = web::Data::new(AppState {
        handlebars,
        oauth2,
    });

    HttpServer::new(move || {
        App::new()
            .wrap(Logger::default())
            .wrap(Logger::new("%a %{User-Agent}i"))
            .wrap(session_middleware())
            .app_data(app_state.clone())
            .service(index)
            .service(bulma)
            .service(github_login)
            .service(github_redirect)
            .service(logout)
    })
        .bind(("0.0.0.0", 8000))?
        .run()
        .await
}