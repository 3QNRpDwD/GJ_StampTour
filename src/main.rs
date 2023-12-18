use actix_web::{
    get, middleware::Logger, web::post, web::resource, web::route, web::Data, web::Json,
    web::Redirect, App, HttpRequest, HttpResponse, HttpServer, Responder,
};
use log::info;
use serde::{Deserialize, Serialize};
use serde_json::from_str;
use serde_with::serde_as;
use std::sync::Mutex;
use std::{env, fs::File, io::Read, path::Path};
use uuid::Uuid;

#[serde_as]
#[derive(Serialize, Deserialize, Debug, Eq, PartialEq, Clone)]
struct Stamp {
    stampId: String,
    stampLocation: String,
    stampName: String,
    stampDesc: String,
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
struct User {
    user_name: String,
    user_id: Uuid,
}

#[derive(Clone)]
struct AddressInfo {
    address: String,
    port: u16,
    protocol: String,
}

#[derive(Clone)]
struct UserList {
    users: Vec<User>,
}

#[get("/")] // 메인폼 요청 처리
async fn index() -> impl Responder {
    match path("html", "index.html").await {
        Ok(v) => HttpResponse::Ok().body(v),
        Err(_) => handle_404().await,
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
        Err(e) => HttpResponse::Ok().body(e),
    }
}

#[get("/check")] // 동적 페이지 요청 처리
async fn handle_check(req: HttpRequest) -> impl Responder {
    // web::Redirect::to(format!("https://stamptour.space/stamp?{}", req.query_string())).permanent() // 진짜 쓸거
    Redirect::to(format!("/stamp?{}", req.query_string())).permanent()
    // 디버깅용
}

#[get("/stamp")]
async fn handle_stamp(req: HttpRequest, StampList: Data<StampList>) -> impl Responder {
    let StampList = StampList.get_ref();

    if !req.query_string().contains("s=") {
        return handle_404().await;
    }

    for stamp in &StampList.stampList {
        if stamp.stampId == req.query_string().split("s=").collect::<Vec<_>>()[1] {
            return HttpResponse::Ok().body(format_file(&stamp.stampName).await);
        }
    }

    handle_404().await
}

async fn handle_login(user_name: Json<UserName>) -> HttpResponse {
    println!("{:?}", user_name.0);
    let user = user_registration(user_name.0);
    // user_list.users.append(user);
    HttpResponse::Ok().json(user.await)
}

async fn user_registration(user_name: UserName) -> User {
    User {
        user_name: user_name.username,
        user_id: Uuid::new_v4(),
    }
}

fn parse_json() -> StampList {
    // 파일 열기
    let StampList: StampList = match File::open("resources/api/stampList.json") {
        Ok(mut file) => {
            let mut file_content = String::new();
            file.read_to_string(&mut file_content).expect("");
            from_str(&file_content).expect("")
        }
        Err(_) => StampList {
            stampList: vec![Stamp {
                stampId: "".to_string(),
                stampLocation: "".to_string(),
                stampName: "".to_string(),
                stampDesc: "".to_string(),
            }],
        },
    };

    StampList
}

async fn format_file(stamp_id: &str) -> String {
    match path("html", "stamp_check_page.html").await {
        Ok(file) => file.replace("%STAMP_ID%", stamp_id),
        Err(_) => "Fail to format".to_string(),
    }
}

#[get("/{file}")]
async fn handle_html(req: HttpRequest) -> impl Responder {
    let split_str: Vec<&str> = req.match_info().query("file").split('.').collect();

    let formatted_file: String; // Declare the formatted_file variable without initializing it.
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
        }
        Err(_) => handle_404().await,
    }
}

// 파일의 경로를 설정하고 read_file 함수를 사용해서 불러옴
async fn path(folder: &str, file: &str) -> Result<String, Vec<u8>> {
    // Use unwrap_or_else to provide a default value in case of an error.
    let file_path = env::current_exe()
        .map(|exe_path| {
            exe_path.parent().map_or(Default::default(), |exe_dir| {
                exe_dir.join(Path::new(&format!("resources\\{}\\{}", folder, file)))
            })
        })
        .unwrap_or_else(|e| {
            // eprintln!("Failed to get the current executable path: {}", e);
            Default::default()
        });

    match read_file(file_path.as_path()).await {
        Ok(v) => Ok(v),
        Err(e) => Err(e),
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

    let split_extension: Vec<&str> = path.to_str().unwrap_or_default().split('.').collect();

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

    let user_list: Data<Mutex<UserList>> = Data::new(Mutex::new(UserList {
        users: vec![User {
            user_name: "".to_string(),
            user_id: Default::default(),
        }],
    }));
    let stamp_list: StampList = parse_json();
    let args: Vec<String> = env::args().collect();

    // Parse command line arguments
    let address_info = AddressInfo {
        address: args
            .get(1)
            .unwrap_or(&String::from("127.0.0.1"))
            .to_string(),
        port: args
            .get(2)
            .unwrap_or(&String::from("80"))
            .parse::<u16>()
            .unwrap(),
        protocol: args.get(3).unwrap_or(&String::from("http")).to_string(),
    };

    let move_address = address_info.clone();

    info!(
        "{}",
        format!(
            "Rust {protocol} Actix-web server started at {protocol}://{address}:{port}",
            protocol = address_info.protocol,
            address = address_info.address,
            port = address_info.port
        )
    );

    HttpServer::new(move || {
        App::new()
            .wrap(Logger::default())
            .app_data(Data::new(stamp_list.clone()))
            .app_data(Data::new(move_address.clone()))
            .app_data(Data::clone(&user_list))
            .service(resource("/login").route(post().to(handle_login)))
            .service(index)
            .service(handle_check)
            .service(handle_stamp)
            .service(handle_html)
            .service(handle_req)
            .default_service(route().to(handle_404))
    })
    .bind((address_info.address.as_str(), address_info.port))?
    .run()
    .await
}
