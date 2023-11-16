use std::{fs::File, io::Read};

use actix_web::{App, get, HttpRequest, HttpResponse, HttpServer, Responder};

#[get("/")]// 메인폼 요청 처리
async fn index() -> impl Responder {
    let mut content:String = String::new();
    match read_file("src/resources/html/index.html".to_string()) {
        Ok(v) => content = v,
        Err(_) => content = "파일을 찾을수없습니다.".to_string()
    }
    HttpResponse::Ok().body(content)
}

#[get("/{folder}/{file}")] // 동적 페이지 요청 처리
async fn handle_req(req: HttpRequest) -> impl Responder {
    match path(&*req.match_info().get("folder").unwrap(), req.match_info().query("file")) {
        Ok(result) => HttpResponse::Ok().body(result),
        Err(e) => HttpResponse::Ok().body(e)
    }
}

// 파일의 경로를 설정하고 read_file 함수를 사용해서 불러옴
fn path(folder: &str, file: &str) -> Result<String, Vec<u8>> {
    match read_file(format!( "src/resources/{}/{}", folder,   file)) {
        Ok(v) => { println!(" 텍스트 파일: {}", file); Ok(v)},
        Err(e) => { println!(" 바이너리 파일: {}", file); Err(e) }
    }
}

// 실제로 파일을 읽는 함수
fn read_file(path: String) -> Result<String, Vec<u8>> {
    let binary_file_list: Vec<&str> = vec!["ico", "png", "webp", "ttf", "woff2", "woff"];
    let mut contents: Vec<u8> = Vec::new();
    let split_extension: Vec<&str> = path.split(".").collect();

    match File::open(path.clone()) {
        Ok(mut file) => {
            file.read_to_end(&mut contents).expect("파일 읽기 실패");
        }
        Err(_) => return Err(contents),
    };

    for &list_extension in binary_file_list.iter() {
        if split_extension.ends_with(&[list_extension]) {
            return Err(contents);
        }
    }

    String::from_utf8(contents.clone()).map_err(|_| contents)
}

// 메인 함수
#[actix_web::main]
async fn main() -> std::io::Result<()> {
    println!("Rust Actix-web server started at 127.0.0.1:8080");

    HttpServer::new(|| {
        App::new()
            .service(index)
            .service(handle_req)
    })
        .bind(("127.0.0.1", 8080))?
        .run()
        .await
}
