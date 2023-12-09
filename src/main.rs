
use std::{fs::File, io::Read};
use std::env;
use std::path::Path;
use serde_with::serde_as;
use serde::{Serialize, Deserialize};
use std::collections::HashMap;
use actix_web::{App, get, HttpRequest, HttpResponse, HttpServer, Responder, web };

#[derive(Debug, Clone, Serialize)]
struct Class {
    class_id: String,
    class_name: String
}

#[derive(Debug, Clone, Serialize)]
struct Stamp {
    stamp_id: String,
    stamp_location:String,
    stamp_name: String,
    stamp_banner: String
}
#[serde_as]
#[derive(Serialize, Deserialize, Debug)]
struct ClassList {
    my_map: HashMap<String, Vec<HashMap<String, String>>>,
}

#[serde_as]
#[derive(Serialize, Deserialize, Debug)]
struct StampList {
    my_map: HashMap<String, Vec<HashMap<String, String>>>,
}


#[get("/")]// 메인폼 요청 처리
async fn index() -> impl Responder {
    match path("html","index.html").await {
        Ok(v) => HttpResponse::Ok().body(v),
        Err(_) => handle_404().await
    }
}

async fn handle_404() -> HttpResponse {
    HttpResponse::NotFound().body(path("html", "Error.html").await.unwrap())
}

// #[get("/api/{file}")]
// async fn handle_api(file: web::Path<String>) -> impl Responder {
//     let mut classList: Class = Class::default();
//     let mut stampList: Stamp = Stamp::default();
//
//     if file.to_string() == "classList.json" {
//         classList = Class::new("a".to_string(), "b".to_string());
//         unsafe {
//             CLASSLIST.push(classList.clone());
//         }
//         web::Json(classList)
//     } else if file.to_string() == "stampList.json" {
//         stampList = Stamp::new("a".to_string(), "b".to_string(), "c".to_string(), "d".to_string());
//         unsafe {
//             STAMPLIST.push(stampList.clone());
//         }
//         web::Json(stampList)
//     } else {
//         // Handle the case when none of the conditions are true
//         web::Json(Default::default()) // You can change this to an appropriate default value
//     }
// }

#[get("/{folder}/{file}")] // 동적 페이지 요청 처리
async fn handle_req(req: HttpRequest) -> impl Responder {
    let folder = req.match_info().get("folder").unwrap();
    match path(&*folder, req.match_info().query("file")).await {
        Ok(result) => HttpResponse::Ok().body(result),
        Err(e) =>  HttpResponse::Ok().body(e)
    }
}

#[get("/check")] // 동적 페이지 요청 처리
async fn handle_check_stamp(req: HttpRequest) -> impl Responder {
    let stamp_id = req.query_string();
    HttpResponse::Ok().body(format_file(stamp_id).await)
}

async fn format_file(stamp_id: &str) -> String {
    match path("html", "stamp_check_page.html").await {
        Ok(file) => {
            file.replace("%STAMP_ID%", stamp_id)
        },
        Err(_) => "Fail to format".to_string()
    }
}

#[get("/{file}")]
async fn handle_html(req: HttpRequest) -> impl Responder {
    let split_str: Vec<&str> = req.match_info().query("file")
        .split('.')
        .collect();

    let formatted_file: String;  // Declare the formatted_file variable without initializing it.
    let file: &str;

    if split_str.len() == 1 {
        formatted_file = format!("{}.html", split_str[0]);
        file = &formatted_file;
    } else {
        file = req.match_info().query("file");
    }

    match path("html", file).await {
        Ok(result) => { if result.contains("(os error 2)") { handle_404().await } else { HttpResponse::Ok().body(result) } },
        Err(_) => handle_404().await
    }
}


// 파일의 경로를 설정하고 read_file 함수를 사용해서 불러옴
async fn path(folder: &str, file: &str) -> Result<String, Vec<u8>> {
    // Use unwrap_or_else to provide a default value in case of an error.
    let file_path = env::current_exe()
        .map(|exe_path| exe_path.parent().map_or(Default::default(), |exe_dir| exe_dir.join(Path::new(&format!( "resources\\{}\\{}", folder,   file)))))
        .unwrap_or_else(|e| {
            eprintln!("Failed to get the current executable path: {}", e);
            Default::default()
        });

    match read_file(file_path.as_path()).await {
        Ok(v) => { println!(" 텍스트 파일: {},", file); Ok(v)},
        Err(e) => { println!(" 바이너리 파일: {}", file); Err(e) }
    }
}

// 실제로 파일을 읽는 함수
async fn read_file(path: &Path) -> Result<String, Vec<u8>> {
    let binary_file_list: Vec<&str> = vec!["ico", "png", "webp", "ttf", "woff2", "woff"];
    let mut contents = Vec::new();

    // Use map_err to convert the error to a string before returning it.
    File::open(path)
        .map_err(|e| {
            println!("파일 {:?} 의 경로를 찾을수 없습니다.", path);
            contents.extend_from_slice(&e.to_string().as_bytes())
        })
        .and_then(|mut file| {
            // Use ? operator for early return in case of an error.
            file.read_to_end(&mut contents).expect("파일 읽기 실패");
            Ok::<String, _>(format!("파일 {:?} 읽기 실패", path))
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

    String::from_utf8(contents.clone()).map_err(|_| contents)
}

// 메인 함수
#[actix_web::main]
async fn main() -> std::io::Result<()> {
    let args: Vec<String> = env::args().collect();
    let mut port = 8080;
    let mut mode = "http";

    match args.len() {
        2 if args[1].parse::<i32>().is_ok() => { port = args[1].parse().unwrap(); }
        2 => { mode = &args[1]; }
        3 if args[2].parse::<i32>().is_ok() => { port = args[2].parse().unwrap(); mode = &args[1]; }
        3 if args[1].parse::<i32>().is_ok() => { port = args[1].parse().unwrap();mode = &args[2]; }
        _ => {}
    }

    println!("Rust {} Actix-web server started at 127.0.0.1:{}", mode, port);

    HttpServer::new(|| {
        App::new()
            .service(index)
            .service(handle_check_stamp)
            .service(handle_html)
            // .service(handle_api)
            .service(handle_req)
            .default_service(web::route().to(handle_404))
    })
        .bind(("127.0.0.1", port))?
        .run()
        .await
}

