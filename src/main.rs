use actix_multipart::form::{tempfile::TempFile, text::Text, MultipartForm};
use actix_session::{storage::CookieSessionStore, Session, SessionMiddleware};
use actix_web::{
    get,
    http::StatusCode,
    middleware, post,
    web::{self, Query, Redirect},
    App, HttpRequest, HttpResponse, HttpServer, Responder,
};
use authentication::{check_session, get_account_id, Account, Credentials};
use handlebars::{DirectorySourceOptions, Handlebars};
use itertools::Itertools;
use log::{error, info};
use rand::random;
use serde::{Deserialize, Serialize};
use serde_json::json;
use std::{fs, io::Read, path::Path, sync::Mutex};
use uuid::Uuid;

mod authentication;
mod config;

/// An uploaded document, containing the uploaded document as a [TempFile] and
/// the document info as a [String]. The uploader should provide the title
/// and tags (the server will select an ID).
#[derive(Debug, MultipartForm)]
struct Upload {
    #[multipart(limit = "64MB")]
    file: TempFile,
    metadata: Text<String>,
}

/// A tag that can be used on documents
#[derive(Debug, Serialize, Deserialize, Clone, PartialEq, Eq, Hash)]
struct Tag {
    name: String,
}

/// Metadata for a document that is provided on upload by the end-user
#[derive(Debug, Serialize, Deserialize, Clone)]
struct UploadedDocument {
    title: String,
    tags: Vec<Tag>,
}

/// A stored document, containing user-provided metadata and a document ID
#[derive(Debug, Serialize, Deserialize, Clone)]
struct StoredDocument {
    uploaded_document: UploadedDocument,
    owner_id: Uuid,
    id: Uuid,
}

/// A simple wrapper around a `Database` for use with a [Mutex]
#[derive(Debug, Serialize, Deserialize)]
struct DatabaseWrapper {
    db: Mutex<Database>,
}

/// A database for storing saved documents and a list of users
#[derive(Debug, Serialize, Deserialize)]
struct Database {
    documents: Vec<StoredDocument>,
    users: Vec<Account>,
}

#[derive(Deserialize)]
struct QueryParams {
    tag: Option<String>,
}

/// Given a template name as the `path`, the desired data to put in the
/// template as `data`, and `hb` for Handlebars, this will produce an
/// `Ok` [HttpResponse] based on the rendered template
fn render_tpl(path: &str, data: serde_json::Value, hb: web::Data<Handlebars<'_>>) -> HttpResponse {
    HttpResponse::Ok().body(hb.render(path, &data).unwrap())
}

/// Given an [Vec] of documents, extract all the unique tags within it.
/// Explicitly, if a tag appears multiple times, it will only be returned
/// once.
fn find_tags(documents: Vec<StoredDocument>) -> Vec<Tag> {
    let mut tags: Vec<Tag> = vec![];
    for mut doc in documents.clone().into_iter() {
        tags.append(&mut doc.uploaded_document.tags);
    }
    tags.into_iter().unique().collect::<Vec<_>>()
}

/// Given a request (possibly containing query parameters), apply
/// the provided filters and return the filtered documents.
fn filter_docs(
    req: HttpRequest,
    session: Session,
    documents: Vec<StoredDocument>,
) -> Vec<StoredDocument> {
    // load the query parameters
    let params = Query::<QueryParams>::from_query(req.query_string()).expect("Param err");

    // create a copy to filter down
    let mut filtered_docs: Vec<StoredDocument> = documents.clone();

    println!("{}", get_account_id(session.clone()));

    // only show documents belonging to the signed-in account
    filtered_docs.retain(|doc| doc.owner_id == get_account_id(session.clone()));

    // apply the tag filter, if present
    if params.tag.is_some() {
        filtered_docs.retain(|doc| {
            doc.uploaded_document.tags.contains(
                &(Tag {
                    name: params
                        .tag
                        .clone()
                        .expect("Tag param absent despite checked")
                        .clone(),
                }),
            )
        });
    }

    // other filters could go here

    // return the filtered documents
    filtered_docs
}

#[get("/signup")]
async fn signup(hb: web::Data<Handlebars<'_>>) -> HttpResponse {
    render_tpl("signup", json!({"theme": "light"}), hb)
}

fn dump_database(db: Database) {
    fs::write(
        "database.json",
        serde_json::to_string_pretty(&db).expect("Creating json for dump failed"),
    )
    .expect("Writing JSON to file failed");
}

#[post("/create-account")]
async fn create_account(
    db: web::Data<DatabaseWrapper>,
    data: web::Form<authentication::Credentials>,
    session: Session,
) -> impl Responder {
    let mut database = db.db.lock().unwrap();
    let selected_uuid = Uuid::new_v4();
    database.users.push(Account {
        credentials: Credentials {
            username: data.username.clone(),
            password: argon2::hash_encoded(
                data.password.as_bytes(),
                &random::<[u8; 32]>(),
                &argon2::Config::default(),
            )
            .expect("Failed hashing password to create user"),
        },
        user_id: selected_uuid,
    });
    dump_database(Database {
        documents: database.documents.clone(),
        users: database.users.clone(),
    });
    session
        .insert("authorized", true)
        .expect("Failed accessing user authorization data.");
    session
        .insert("account_uuid", selected_uuid)
        .expect("Failed accessing user UUID data.");
    Redirect::to("/").see_other()
}

#[get("/")]
async fn docs(
    req: HttpRequest,
    hb: web::Data<Handlebars<'_>>,
    db: web::Data<DatabaseWrapper>,
    session: Session,
) -> impl Responder {
    if check_session(session.clone()) {
        let db_data = db.db.lock().unwrap();
        let db_docs = db_data.documents.clone();
        let db_users = db_data.documents.clone();
        render_tpl(
            "docs",
            json!({
                "documents": *filter_docs(req, session.clone(), db_docs.clone()),
                "theme": "light",
                "users": *db_users,
                "tags": find_tags(db_docs.clone())
            }),
            hb,
        )
    } else {
        render_tpl("login", json!({"theme": "light"}), hb)
    }
}

fn load_document(id: Uuid) -> Vec<u8> {
    fs::read(format!("uploads/{}.pdf", id.to_string())).unwrap()
}

#[get("/docs/{id}/download")]
async fn docs_id_download(
    id: web::Path<String>,
    db: web::Data<DatabaseWrapper>,
    session: Session,
) -> impl Responder {
    match Uuid::parse_str(id.as_str()) {
        Ok(document_uuid) => {
            let data = db.db.lock().unwrap();
            for doc in data.documents.clone() {
                if doc.id == document_uuid && doc.owner_id == get_account_id(session.clone()) {
                    return HttpResponse::build(StatusCode::OK)
                        .content_type("application/pdf")
                        .body(load_document(document_uuid));
                }
            }
            HttpResponse::build(StatusCode::FORBIDDEN)
                .body("Unauthorized: you don't have access to that document.")
        }
        Err(err) => {
            eprintln!("{}", err);
            HttpResponse::build(StatusCode::INTERNAL_SERVER_ERROR).body(err.to_string())
        }
    }
}

#[post("/docs/upload")]
async fn docs_upload(
    MultipartForm(form): MultipartForm<Upload>,
    db: web::Data<DatabaseWrapper>,
    session: Session,
) -> impl Responder {
    // save the provided metadata, then attempt to decode it into an
    // UploadedDocument struct
    let raw_metadata: Result<UploadedDocument, serde_json::Error> =
        serde_json::from_str(&form.metadata.0);
    match raw_metadata {
        Ok(metadata) => {
            // this UUID will be used as the document ID in the database
            let file_uuid = uuid::Uuid::new_v4();

            // file path to put the saved file in
            let destination_filename = format!(
                "{}{}.pdf",
                config::get_config().upload_path,
                file_uuid.to_string().as_str()
            );

            // UUID of the currently signed-in account
            let account_uuid = session
                .get::<Uuid>("account_uuid")
                .expect("Failed to access user UUID from session")
                .expect("Failed to access user UUID from session");
            let saved_doc = StoredDocument {
                uploaded_document: metadata,
                id: file_uuid,
                owner_id: account_uuid,
            };
            let mut temp_file = form.file.file;
            let mut buffer: Vec<u8> = vec![];
            temp_file.read_to_end(&mut buffer);
            fs::write(destination_filename, buffer);
            let mut db_x = db.db.lock().unwrap();
            db_x.documents.push(saved_doc);
            info!("Writing updated database to file...");
            dump_database(Database {
                documents: db_x.documents.clone(),
                users: db_x.users.clone(),
            });
            info!("{:#?}", db_x);
            HttpResponse::Ok().body("File uploaded successfully")
        }
        Err(e) => {
            error!("{}", e);
            HttpResponse::BadRequest().body("Error decoding JSON.")
        }
    }
}

#[post("/logout")]
async fn logout(session: Session) -> Redirect {
    session.clear();
    Redirect::to("/").see_other()
}

#[post("/auth")]
async fn auth(
    db: web::Data<DatabaseWrapper>,
    data: web::Form<authentication::Credentials>,
    session: Session,
) -> Redirect {
    if let Ok(account) =
        authentication::check_credentials(data.0.clone(), db.db.lock().unwrap().users.clone())
    {
        session
            .insert("authorized", true)
            .expect("Failed accessing user authorization data.");
        session
            .insert("account_uuid", account.user_id)
            .expect("Failed accessing user UUID data.");
        Redirect::to("/").see_other()
    } else {
        Redirect::to("/?err=1").see_other()
    }
}

#[get("/static/signedout.css")]
async fn static_signedout_css() -> impl Responder {
    HttpResponse::Ok().body(fs::read_to_string("static/signedout.css").unwrap())
}

fn load_database<P: AsRef<Path>>(path: P) -> Database {
    // try reading the database file, but if reading it fails (for example, if
    // the file doesn't exist), return an empty database instead
    match fs::read_to_string(path) {
        Ok(data) => serde_json::from_str(data.as_str()).expect("Error parsing DB"),
        Err(_) => Database {
            users: vec![],
            documents: vec![],
        },
    }
}

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    // set up logging
    env_logger::init();

    // set up Handlebars
    let mut hbs = Handlebars::new();
    hbs.register_templates_directory(
        "templates",
        DirectorySourceOptions {
            tpl_extension: ".html".to_owned(),
            hidden: false,
            temporary: false,
        },
    )
    .unwrap();
    let hbs_ref = web::Data::new(hbs);

    let db = web::Data::new(DatabaseWrapper {
        db: Mutex::new(load_database("database.json")),
    });

    HttpServer::new(move || {
        App::new()
            .wrap(middleware::NormalizePath::trim())
            .wrap(middleware::Logger::default())
            .wrap(SessionMiddleware::new(
                CookieSessionStore::default(),
                authentication::get_secret_key().clone(),
            ))
            .app_data(hbs_ref.clone())
            .app_data(db.clone())
            .service(docs)
            .service(signup)
            .service(docs_id_download)
            .service(docs_upload)
            .service(auth)
            .service(logout)
            .service(create_account)
            .service(static_signedout_css)
    })
    .workers(config::get_config().workers)
    .bind((
        config::get_config().listen_addr,
        config::get_config().listen_port,
    ))?
    .run()
    .await
}
