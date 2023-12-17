
use std::{fs::File, io::Read, env , path::Path};
use std::os::raw::c_char;
use serde_with::serde_as;
use serde::{Serialize, Deserialize};
use serde_json::from_str;
use actix_web::{middleware, App, get, HttpRequest, HttpResponse, HttpServer, Responder, web };
use log::info;
use regex::Regex;
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

#[derive(Debug, Serialize, Deserialize, Clone)]
struct UserName {
    username: String,
}

#[serde_as]
#[derive(Serialize, Deserialize, Debug, Clone)]
struct Userid {
    user_name: String,
    user_id: Uuid
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
    web::Redirect::to(format!("http://192.168.0.9:80/stamp?{}", req.query_string())).permanent() // 디버깅용
}

#[get("/stamp")]
async fn handle_stamp(req: HttpRequest, StampList: web::Data<StampList>) -> impl Responder {
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

async fn handle_login(user_name: web::Json<UserName>, req: HttpRequest) -> HttpResponse {
    HttpResponse::Ok().json(user_registration(user_name.0))
}

fn user_registration(user_name: UserName) -> Userid{
    Userid {
        user_name: user_name.username,
        user_id: uuid::Uuid::new_v4(),
    }
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
            // eprintln!("Failed to get the current executable path: {}", e);
            Default::default()
        });

    match read_file(file_path.as_path()).await {
        Ok(v) => Ok(v),
        Err(e) =>  Err(e)
    }
}

// 실제로 파일을 읽는 함수
async fn read_file(path: &Path) -> Result<String, Vec<u8>> {
    let binary_file_list: Vec<&str> = vec!["ico", "png", "webp", "ttf", "woff2", "woff"];
    let mut contents = Vec::new();

    // Use map_err to convert the error to a string before returning it.
    File::open(path)
        .map_err(|e| {
            // println!("파일 {:?} 의 경로를 찾을수 없습니다.", path);
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
    env_logger::init_from_env(env_logger::Env::new().default_filter_or("info"));

    let StampList: StampList = parse_json();
    let args: Vec<String> = env::args().collect();

    // Set default values
    let default_address = "127.0.0.1".to_string();
    let default_port = "80".to_string();
    let default_protocol = "http".to_string();

    // Parse command line arguments
    let address = args.get(1).unwrap_or(&default_address).to_string();
    let port = args.get(2).unwrap_or(&default_port).parse::<u16>().unwrap_or(80);
    let protocol = args.get(3).unwrap_or(&default_protocol).to_string();

    info!("Rust {} Actix-web server started at http://{}:{}", protocol, address, port);

    HttpServer::new(move || {
        App::new()
            .wrap(middleware::Logger::default())
            .app_data(web::Data::new(StampList.clone()))
            .service(web::resource("/login").route(web::post().to(handle_login)))
            .service(index)
            .service(handle_check)
            .service(handle_stamp)
            .service(handle_html)
            .service(handle_req)
            .default_service(web::route().to(handle_404))
    })
        .bind((address.as_str(), port))?
        .run()
        .await
}


