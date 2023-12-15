
use std::{fs::File, io::Read, env };
use std::path::Path;
use serde_with::serde_as;
use serde::{Serialize, Deserialize};
use serde_json::from_str;
use actix_web::{App, get, HttpRequest, HttpResponse, HttpServer, Responder, web };
use uuid::Uuid;


#[serde_as]
#[derive(Serialize, Deserialize, Debug, Eq, PartialEq, Clone)]
struct Stamp {
    stampId: String,
    stampLocation:String,
    stampName: String,
    stampDesc: String
}

#[serde_as]
#[derive(Serialize, Deserialize, Debug, Clone)]
struct StampList {
    stampList: Vec<Stamp>,
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

#[get("/{folder}/{file}")] // 동적 페이지 요청 처리
async fn handle_req(req: HttpRequest) -> impl Responder {
    let folder = req.match_info().get("folder").unwrap();
    match path(&*folder, req.match_info().query("file")).await {
        Ok(result) => HttpResponse::Ok().body(result),
        Err(e) =>  HttpResponse::Ok().body(e)
    }
}

#[get("/check")] // 동적 페이지 요청 처리
async fn handle_check(req: HttpRequest) -> impl Responder {
    // web::Redirect::to(format!("https://stamptour.space/stamp?{}", req.query_string())).permanent() // 진짜 쓸거
    web::Redirect::to(format!("http://127.0.0.1:8080/stamp?{}", req.query_string())).permanent() // 디버깅용
}

#[get("/stamp")]
async fn handle_stamp(req: HttpRequest, StampList: web::Data<StampList>) -> impl Responder {
    println!("접속");
    let query_stamp = req.query_string().split("s=").collect::<Vec<_>>()[1];
    let StampList = StampList.get_ref();

    for stamp in &StampList.stampList {
        if stamp.stampId == query_stamp {
            return HttpResponse::Ok().body(format_file(&stamp.stampName).await);
        }
    }

    // If no matching stamp is found, return a default response
    HttpResponse::Ok().body(format_file(&query_stamp).await)
}


fn parse_json() -> StampList {
    // 파일 열기
    let mut file = File::open("resources/api/stampList.json").expect("Failed to open file");

    // 파일 내용을 문자열로 읽기
    let mut file_content = String::new();
    file.read_to_string(&mut file_content)
        .expect("Failed to read file content");

    // JSON 문자열을 역직렬화하여 구조체로 변환
    let StampList: StampList = from_str(&file_content).expect("Failed to deserialize JSON");

    StampList

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
        Ok(result) => {
            if result.contains("(os error 2)") {
                handle_404().await
            } else {
                HttpResponse::Ok().body(result)
            }
        },
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
    let StampList: StampList = parse_json();
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

    HttpServer::new(move || {
        App::new()
            .app_data(web::Data::new(StampList.clone()))
            .service(index)
            .service(handle_check)
            .service(handle_stamp)
            .service(handle_html)
            // .service(handle_api)
            .service(handle_req)
            .default_service(web::route().to(handle_404))
    })
        .bind(("127.0.0.1", port))?
        .run()
        .await
}

