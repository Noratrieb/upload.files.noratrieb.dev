use axum::{
    body::Bytes,
    extract::{DefaultBodyLimit, Multipart, Request, State},
    http::{header, StatusCode},
    middleware::Next,
    response::{Html, IntoResponse, Redirect, Response},
    routing::{get, post},
    Router,
};
use base64::Engine;
use color_eyre::eyre::{self, bail, Context};
use color_eyre::{eyre::OptionExt, Result};
use object_store::ObjectStore;
use rand_core::TryRngCore;
use tower::ServiceBuilder;
use tracing::{error, info, level_filters::LevelFilter};
use tracing_subscriber::EnvFilter;

#[derive(Clone)]
struct Config {
    username: String,
    password: String,
    s3_client: object_store::aws::AmazonS3,
}

#[tokio::main(flavor = "current_thread")]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::builder()
                .with_default_directive(LevelFilter::INFO.into())
                .from_env_lossy(),
        )
        .init();

    let env = |name: &str| {
        std::env::var(name).wrap_err_with(|| format!("could not find environment variable {name}"))
    };

    let username = env("UPLOAD_FILES_NORATRIEB_DEV_USERNAME")?;
    let password = env("UPLOAD_FILES_NORATRIEB_DEV_PASSWORD")?;

    let s3_client = object_store::aws::AmazonS3Builder::new()
        .with_bucket_name(env("UPLOAD_FILES_NORATRIEB_DEV_BUCKET")?)
        .with_access_key_id(env("UPLOAD_FILES_NORATRIEB_DEV_KEYID")?)
        .with_secret_access_key(env("UPLOAD_FILES_NORATRIEB_DEV_ACCESS_KEY")?)
        .with_endpoint(env("UPLOAD_FILES_NORATRIEB_DEV_ENDPOINT")?)
        .with_region(env("UPLOAD_FILES_NORATRIEB_DEV_REGION")?)
        .with_allow_http(true)
        .build()
        .wrap_err("failed to build client")?;

    let state = Config {
        username,
        password,
        s3_client,
    };

    let app = Router::new()
        .route("/", get(index))
        .route("/", post(upload))
        .with_state(state.clone())
        .layer(
            ServiceBuilder::new()
                .layer(tower_http::trace::TraceLayer::new_for_http())
                // raise limit to 100MB
                .layer(DefaultBodyLimit::max(100_000_000))
                .layer(axum::middleware::from_fn_with_state(state, auth_middleware)),
        );

    let addr = "0.0.0.0:3050";
    let listener = tokio::net::TcpListener::bind(addr)
        .await
        .wrap_err("binding listener")?;
    info!(?addr, "Starting server");

    axum::serve(listener, app).await.wrap_err("failed to serve")
}

async fn index() -> impl IntoResponse {
    Html(include_str!("../index.html"))
}

async fn upload(State(config): State<Config>, multipart: Multipart) -> Result<Response, Response> {
    let req = parse_req(multipart).await.map_err(|err| {
        info!(?err, "Bad request for upload");
        (StatusCode::BAD_REQUEST, err.to_string()).into_response()
    })?;

    info!(path = ?req.name, "Uploading file");

    config
        .s3_client
        .put_opts(
            &req.name,
            object_store::PutPayload::from_bytes(req.bytes),
            object_store::PutOptions {
                mode: object_store::PutMode::Create,
                tags: Default::default(),
                attributes: Default::default(),
                extensions: Default::default(),
            },
        )
        .await
        .map_err(|err| match err {
            object_store::Error::AlreadyExists { .. } => {
                info!(
                    "Not uploading to {} because the path already exists",
                    req.name
                );
                (
                    StatusCode::CONFLICT,
                    format!("path already exists: {}", req.name),
                )
                    .into_response()
            }
            _ => {
                let err = eyre::ErrReport::new(err);
                error!(?err, "failed to upload");
                (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()).into_response()
            }
        })?;

    info!(path = ?req.name, "Successfully uploaded file");

    Ok(Redirect::to(&format!("https://files.noratrieb.dev{}", req.name)).into_response())
}

struct UploadRequest {
    name: object_store::path::Path,
    bytes: Bytes,
}

async fn parse_req(mut multipart: Multipart) -> Result<UploadRequest> {
    let mut name = None;
    let mut file = None;
    let mut secret = false;
    while let Some(field) = multipart
        .next_field()
        .await
        .wrap_err("reading next field")?
    {
        match field.name() {
            Some("filename") => {
                let value = field.text().await.wrap_err("failed to get filename text")?;
                if !value.is_empty() {
                    name = Some(value);
                }
            }
            Some("file") => {
                if name.is_none() {
                    name = Some(
                        field
                            .file_name()
                            .ok_or_eyre("missing filename for file field")?
                            .to_owned(),
                    );
                }

                file = Some(
                    field
                        .bytes()
                        .await
                        .wrap_err("failed to read file contents")?,
                );
            }
            Some("secret") => {
                let text = field.text().await.wrap_err("reading secret contents")?;
                if text == "on" {
                    secret = true;
                }
            }
            _ => {}
        }
    }

    let mut name = name.ok_or_eyre("missing name")?;

    if name.contains('/') {
        bail!("name must not contain slashes: '{name}'")
    }

    if name.is_empty() {
        bail!("name must not be empty");
    }

    if secret {
        let mut random = [0_u8; 32];
        rand_core::OsRng.try_fill_bytes(&mut random).unwrap();
        let random = bs58::encode(&random).into_string();

        name = format!("{random}/{name}");
    }

    name = format!("/{name}");

    let path =
        object_store::path::Path::parse(&name).wrap_err_with(|| format!("invalid path: {name}"))?;

    Ok(UploadRequest {
        name: path,
        bytes: file.ok_or_eyre("missing file")?,
    })
}

#[axum::debug_middleware]
async fn auth_middleware(State(config): State<Config>, request: Request, next: Next) -> Response {
    match check_auth(config, request).await {
        Ok(request) => next.run(request).await,
        Err(err) => err,
    }
}

async fn check_auth(config: Config, request: Request) -> Result<Request, Response> {
    let Some(header) = request.headers().get(header::AUTHORIZATION) else {
        return Err(reject_auth("missing authorization header"));
    };

    let header = header
        .to_str()
        .map_err(|_| reject_auth("authorization header is invalid UTF-8"))?;

    let Some(("Basic", value)) = header.split_once(' ') else {
        return Err(reject_auth(
            "invalid authorization header, missing 'Basic '",
        ));
    };

    let decoded = String::from_utf8(
        base64::prelude::BASE64_STANDARD
            .decode(value)
            .map_err(|_| reject_auth("invalid base64 value"))?,
    )
    .map_err(|_| reject_auth("invalid UTF-8 after base64 decode"))?;

    let Some((username, password)) = decoded.split_once(':') else {
        return Err(reject_auth("missing : between username and password"));
    };

    if username != config.username {
        return Err(reject_auth("invalid username"));
    }
    if subtle::ConstantTimeEq::ct_ne(password.as_bytes(), config.password.as_bytes()).into() {
        return Err(reject_auth("invalid password"));
    }

    Ok(request)
}

fn reject_auth(reason: &str) -> Response {
    info!("Rejecting request authentication due to {reason}");
    (
        StatusCode::UNAUTHORIZED,
        [(
            header::WWW_AUTHENTICATE,
            "Basic realm=\"upload.files.noratrieb.dev\"",
        )],
    )
        .into_response()
}
