use std::{fs::File, io::Read};
use std::env;
use std::path::Path;

use actix_web::{App, get, HttpRequest, HttpResponse, HttpServer, Responder};

#[get("/")]// 메인폼 요청 처리
async fn index() -> impl Responder {
    let mut content:String = String::new();
    match path("html","index.html") {
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
    println!("요청 경로 : /{}/{}", folder, file);
    // Use unwrap_or_else to provide a default value in case of an error.
    let file_path = env::current_exe()
        .map(|exe_path| exe_path.parent().map_or(Default::default(), |exe_dir| exe_dir.join(Path::new(&format!( "resources/{}/{}", folder,   file)))))
        .unwrap_or_else(|e| {
            eprintln!("Failed to get the current executable path: {}", e);
            Default::default()
        });

    println!("실제 경로 : {:?}", file_path);
    match read_file(file_path.as_path()) {
        Ok(v) => { println!(" 텍스트 파일: {}", file); Ok(v)},
        Err(e) => { println!(" 바이너리 파일: {}", file); Err(e) }
    }
}

// 실제로 파일을 읽는 함수
fn read_file(path: &Path) -> Result<String, Vec<u8>> {
    let binary_file_list: Vec<&str> = vec!["ico", "png", "webp", "ttf", "woff2", "woff"];
    let mut contents = Vec::new();

    // Use map_err to convert the error to a string before returning it.
    File::open(path)
        .map_err(|e| {
            println!("파일 {:?} 읽기 오류 : {}", path, e);
            e.to_string()
        })
        .and_then(|mut file| {
            // Use ? operator for early return in case of an error.
            file.read_to_end(&mut contents).expect("파일 읽기 실패");
            Ok(())
        })
        .ok(); // Ignore the result since it's already logged.

    let split_extension: Vec<&str> = path
        .to_str()
        .unwrap_or_default()
        .split('.')
        .collect();

    if let Some(&list_extension) = split_extension.last() {
        if binary_file_list.contains(&list_extension) {
            return Err(contents);
        }
    }

    println!("파일 읽기 성공 : {}", path.to_string_lossy());
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
