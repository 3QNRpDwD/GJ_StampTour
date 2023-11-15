use std::fs::{File, read};
use std::io::Read;
use actix_web::{get, post, web, App, HttpResponse, HttpServer, Responder, HttpRequest};

#[derive(Debug)]
enum FileType {
    HTML,
    CSS,
    JS,
    Fonts,
    Images,
    Icon
}

#[get("/")]
async fn index() -> impl Responder {
    let a = read_file("src/resources/html/index.html".to_string());
    let content = String::from_utf8(a);
    HttpResponse::Ok().body(content.unwrap())
}

#[get("/html/{file}")] // <- 경로 매개변수 정의
async fn handle_html(req: HttpRequest) -> impl Responder {
    if let Ok(result) = path(FileType::HTML, req.match_info().query("file")) {
        HttpResponse::Ok().body(result)
    } else {
        HttpResponse::Ok().body("파일 형식이 올바르지 않습니다.")
    }
}

#[get("/css/{file}")] // <- 경로 매개변수 정의
async fn handle_css(req: HttpRequest) -> impl Responder {
    match path(FileType::CSS, req.match_info().query("file")) {
        Ok(result) => HttpResponse::Ok().body(result),
        _ => HttpResponse::Ok().body("파일 형식이 올바르지 않습니다.")
    }
}

#[get("/js/{file}")] // <- 경로 매개변수 정의
async fn handle_js(req: HttpRequest) -> impl Responder {
    match path(FileType::JS, req.match_info().query("file")) {
        Ok(result) => HttpResponse::Ok().body(result),
        _ => HttpResponse::Ok().body("파일 형식이 올바르지 않습니다.")
    }
}

#[get("/fonts/{file}")] // <- 경로 매개변수 정의
async fn handle_fonts(req: HttpRequest) -> impl Responder {
    match path(FileType::Fonts, req.match_info().query("file")) {
        Err(result) => HttpResponse::Ok().body(result),
        _ => HttpResponse::Ok().body("파일 형식이 올바르지 않습니다.")
    }
}

#[get("/images/{file}")] // <- 경로 매개변수 정의
async fn handle_images(req: HttpRequest) -> impl Responder {
    match path(FileType::Images, req.match_info().query("file")) {
        Err(result) => HttpResponse::Ok().body(result),
        _ => HttpResponse::Ok().body("파일 형식이 올바르지 않습니다.")
    }
}

#[get("/icon/{file}")] // <- 경로 매개변수 정의
async fn handle_icon(req: HttpRequest) -> impl Responder {
    match path(FileType::Icon, req.match_info().query("file")) {
        Err(result) => HttpResponse::Ok().body(result),
        _ => HttpResponse::Ok().body("파일 형식이 올바르지 않습니다.")
    }
}

fn path(extension: FileType, file: &str) -> Result<String, Vec<u8>> {
    let mut buf:Vec<u8> = Vec::new();
    match extension {
        FileType::HTML =>   buf = read_file(format!( "src/resources/{}/{}", "html",   file)),
        FileType::CSS =>    buf = read_file(format!( "src/resources/{}/{}", "css",    file)),
        FileType::JS =>     buf = read_file(format!( "src/resources/{}/{}", "js",     file)),
        FileType::Fonts =>  buf = read_file(format!( "src/resources/{}/{}", "fonts",  file)),
        FileType::Images => buf = read_file(format!( "src/resources/{}/{}", "images", file)),
        FileType::Icon =>   buf = read_file(format!( "src/resources/{}/{}", "icon",   file)),
    };
    match String::from_utf8(buf.clone()) {
        Ok(v) => Ok(v),
        Err(e) => Err(buf),
    }
}

fn read_file(path: String) -> Vec<u8> {
    println!("{}", path);
    let mut f = File::open(path).expect("file not found");

    let mut contents: Vec<u8> = Vec::new();

    f.read_to_end(&mut contents).expect("Something went wrong reading the file");

   contents
}

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    println!("Rust Actix-web server started at 127.0.0.1:8080");

    HttpServer::new(|| {
        App::new()
            .service(index)
            .service(handle_html)
            .service(handle_css)
            .service(handle_js)
            // .service(handle_fonts)
            // .service(handle_images)
            // .service(handle_icon)
    })
        .bind(("127.0.0.1", 8080))?
        .run()
        .await
}
