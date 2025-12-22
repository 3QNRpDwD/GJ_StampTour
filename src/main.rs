use actix_web::{
    cookie::Cookie,
    middleware::Logger,
    web::{get, post, resource, route, Data, Json},
    App, HttpRequest, HttpResponse, HttpServer, Responder,
};
use chrono;
use log::{debug, error, info, warn};
use serde::{Deserialize, Serialize};
use serde_json::from_str;
use std::{
    collections::{BTreeMap, HashMap, HashSet},
    env,
    fs::File,
    io::Read,
    path::Path,
    sync::Mutex,
};
use std::panic::panic_any;
use actix_web::web::Redirect;
use rand::Rng;
use uuid::Uuid;

use std::str::FromStr;
use lazy_static::lazy_static;

lazy_static! {
    static ref NAMESPACE_UUID: Uuid =
        Uuid::from_str("6ba7b810-9dad-11d1-80b4-00c04fd430c8")
            .expect("Failed to parse NAMESPACE_UUID");
}



#[derive(Clone, Debug)]
struct OtpAuth {
    student_id: String,
    generation_time: i64,
    expiration_time: i64,
}

type OtpStore = HashMap<String, OtpAuth>;

#[derive(Serialize, Clone, Debug)]
struct SuccessfulOtpInfo {
    otp: String,
    stamp_id: String,
    timestamp: i64,
}

type UserSuccessHistory = HashMap<String, SuccessfulOtpInfo>;

#[derive(Serialize)]
struct GenerateOtpResponse {
    new_otp: String,
    previous_success: Option<SuccessfulOtpInfo>,
}

#[derive(Deserialize, Debug)]
struct KioskStampRequest {
    otp: String,
    stamp_id: String,
}

#[derive(Serialize, Deserialize, Debug, Eq, PartialEq, Clone, Hash)]
struct Stamp {
    stampId: String,
    stampLocation: String,
    stampName: String,
    stampDesc: String,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
struct StampList {
    stampList: HashSet<Stamp>,
}

#[derive(Debug, Clone)]
struct StampIdList {
    stamp_id_list: BTreeMap<String, Stamp>,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
struct LoginRequest {
    user: String,
    password: String,
}

#[derive(Serialize, Deserialize, Debug, Clone, Hash)]
struct User {
    student_id: String,
    user_name: String,
    password_hash: String,
    user_agent: String,
}

#[derive(Clone)]
struct AddressInfo {
    address: String,
    port: u16,
    protocol: String,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
struct UserList {
    users: BTreeMap<String, User>,
}

#[derive(Debug, Clone)]
struct UserStampList {
    user_stamp_list: HashMap<String, String>,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
struct StampHistory {
    stamp_history: HashMap<String, Vec<StampUserInfo>>,
}

#[derive(Serialize, Deserialize, Debug, Clone, Hash)]
struct StampUserInfo {
    student_id: String,
    user_name: String,
    timestamp: String,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
struct Command {
    command: String,
    output: String,
}

#[derive(Serialize)]
struct LoginResponse {
    user_id: String,
    user_name: String,
}

use actix_web::http::header; // 헤더 처리를 위해 추가

// 로깅 컨텍스트를 돕기 위한 헬퍼 함수
fn get_client_ip(req: &HttpRequest) -> String {
    req.peer_addr().map_or_else(|| "unknown".to_string(), |a| a.ip().to_string())
}

fn get_user_agent(req: &HttpRequest) -> String {
    req.headers()
        .get(header::USER_AGENT)
        .and_then(|h| h.to_str().ok())
        .unwrap_or("unknown")
        .to_string()
}

// User Agent가 기존 로그인 정보와 일치하는지 확인하고 로그용 태그 반환
fn check_ua_consistency(current_ua: &str, stored_ua: &str) -> String {
    if current_ua == stored_ua {
        "MATCH".to_string()
    } else {
        format!("MISMATCH(Reg: {}...)", &stored_ua.chars().take(20).collect::<String>())
    }
}

/// 메인 폼 요청을 처리하는 비동기 함수입니다. 'index.html' 파일을 읽어와서
/// 200 OK 응답으로 반환합니다.
///
/// # Returns
///
/// 성공적으로 'index.html' 파일을 읽은 경우, 해당 파일의 내용을 담은 200 OK 응답이 반환됩니다.
/// 파일이 존재하지 않거나 읽기에 실패한 경우 404 Not Found 응답이 반환됩니다.
///
/// # Example
///
/// ```rust
/// #[actix_web::main]
/// async fn main() {
///     // Actix-web 앱 생성 및 라우터 등록
///     let app = App::new().service(index);
///     // HTTP 서버 생성 및 실행
///     HttpServer::new(|| {
///         app.clone()
///     })
///     .bind("127.0.0.1:8080").unwrap()
///     .run()
///     .await
///     .unwrap();
/// }
/// ```
async fn index() -> impl Responder {
    // path 함수를 사용하여 'index.html' 파일 읽기 시도
    match path("html", "index.html").await {
        Ok(v) => HttpResponse::Ok().body(v), // 파일이 성공적으로 읽혔을 경우 200 OK 응답과 파일 내용 반환
        Err(_) => handle_404().await,        // 파일이 존재하지 않는 경우 404 Not Found 응답 반환
    }
}

/// 404 Not Found 응답을 처리하는 비동기 함수입니다. 'error404.html' 파일을 읽어와서
/// 404 Not Found 응답으로 반환합니다.
///
/// # Returns
///
/// 'error404.html' 파일을 읽은 경우, 해당 파일의 내용을 담은 404 Not Found 응답이 반환됩니다.
/// 파일이 존재하지 않거나 읽기에 실패한 경우 "File not found" 메시지가 담긴 404 Not Found 응답이 반환됩니다.
///
/// # Example
///
/// ```rust
/// #[actix_web::main]
/// async fn main() {
///     // Actix-web 앱 생성 및 라우터 등록
///     let app = App::new().default_service(route().to(handle_404));
///     // HTTP 서버 생성 및 실행
///     HttpServer::new(|| {
///         app.clone()
///     })
///     .bind("127.0.0.1:8080").unwrap()
///     .run()
///     .await
///     .unwrap();
/// }
/// ```
async fn handle_404() -> HttpResponse {
    // 404 Not Found 응답과 'error404.html' 파일 내용 반환
    HttpResponse::NotFound()
        .insert_header(("Cache-Control", "no-cache"))
        .body(path("html", "error404.html").await.unwrap_or_default())
}

/// 401 Unauthorized 응답을 처리하는 비동기 함수입니다. 'error401.html' 파일을 읽어와서
/// 401 Unauthorized 응답으로 반환합니다.
///
/// # Returns
///
/// 'error401.html' 파일을 읽은 경우, 해당 파일의 내용을 담은 401 Unauthorized 응답이 반환됩니다.
/// 파일이 존재하지 않거나 읽기에 실패한 경우 "File not found" 메시지가 담긴 401 Unauthorized 응답이 반환됩니다.
///
/// # Example
///
/// ```rust
/// #[actix_web::main]
/// async fn main() {
///     // Actix-web 앱 생성 및 라우터 등록
///     let app = App::new().default_service(route().to(handle_401));
///     // HTTP 서버 생성 및 실행
///     HttpServer::new(|| {
///         app.clone()
///     })
///     .bind("127.0.0.1:8080").unwrap()
///     .run()
///     .await
///     .unwrap();
/// }
/// ```
async fn handle_401() -> HttpResponse {
    // 401 Unauthorized 응답과 'error401.html' 파일 내용 반환
    HttpResponse::Unauthorized()
        .insert_header(("Cache-Control", "no-cache"))
        .body(path("html", "error401.html").await.unwrap_or_default())
}

/// 동적 페이지 요청을 처리하는 비동기 함수입니다. 요청된 폴더 및 파일명을 사용하여 파일을 읽어와서
/// HTTP 응답으로 반환합니다.
///
/// # Arguments
///
/// * `req` - `HttpRequest` 객체로, 동적 페이지 요청에 대한 정보를 포함합니다.
///
/// # Returns
///
/// 텍스트 파일이나 바이너리 파일을 읽을경우, 해당 파일의 내용을 담은 200 OK 응답이 반환됩니다.
/// 파일이 존재하지 않거나 읽기에 실패한 경우 404 Not Found 응답이 반환됩니다.
///
/// # Example
///
/// ```rust
/// #[actix_web::main]
/// async fn main() {
///     // Actix-web 앱 생성 및 라우터 등록
///     let app = App::new().service(handle_req);
///     // HTTP 서버 생성 및 실행
///     HttpServer::new(|| {
///         app.clone()
///     })
///     .bind("127.0.0.1:8080").unwrap()
///     .run()
///     .await
///     .unwrap();
/// }
/// ```
async fn handle_req(req: HttpRequest) -> impl Responder {
    let folder = req.match_info().get("folder").unwrap();
    let file_name = req.match_info().query("file");
    let ip = get_client_ip(&req);

    // [변경] 파일 요청은 DEBUG 레벨로 기록하여 평소에는 숨김
    log::debug!("[File Request] [IP: {}] {}/{}", ip, folder, file_name);

    match path(&*folder, file_name).await {
        Ok(result) => {
            if result.contains("File not found file error") {
                // 파일이 없을 때만 Warn/Error 레벨 유지
                warn!("[File Not Found] [IP: {}] {}/{}", ip, folder, file_name);
                handle_404().await
            } else {
                HttpResponse::Ok().body(result)
            }
        }
        Err(error) => HttpResponse::Ok().body(error),
    }
}

/// 스템프 확인 및 찍기 요청을 처리하는 비동기 함수입니다. 유저의 쿠키를 확인하고,
/// 유저가 등록된 사용자인지, 스템프 ID가 유효한지 확인한 후, 유저의 스템프를 갱신합니다.
///
/// # Arguments
///
/// * `req` - `HttpRequest` 객체로, 요청에 대한 정보를 포함합니다.
/// * `user_list` - 등록된 사용자 정보를 관리하는 `UserList`에 대한 `Data<Mutex<UserList>>`입니다.
/// * `stamp_id_list` - 유효한 스템프 ID 정보를 관리하는 `StampIdList`에 대한 `Data<StampIdList>`입니다.
/// * `user_stamp_list` - 유저의 스템프 정보를 관리하는 `UserStampList`에 대한 `Data<Mutex<UserStampList>>`입니다.
///
/// # Returns
///
/// 유저의 쿠키 및 스템프 ID가 유효한 경우, 유저의 스템프를 갱신하고 임시적인 리다이렉션(307)을 반환합니다.
/// 유저의 쿠키가 없거나, 등록된 사용자가 아닌 경우, 유효한 스템프 ID가 아닌 경우, 같이 리다이렉션을 반환합니다.
///
/// # Example
///
/// ```rust
/// #[actix_web::main]
/// async fn main() {
///     // Actix-web 앱 생성 및 라우터 등록
///     let app = App::new().service(handle_check);
///     // HTTP 서버 생성 및 실행
///     HttpServer::new(|| {
///         app.clone()
///     })
///     .bind("127.0.0.1:8080").unwrap()
///     .run()
///     .await
///     .unwrap();
/// }
/// ```
async fn handle_check(
    req: HttpRequest,
    user_list: Data<Mutex<UserList>>,
    stamp_id_list: Data<StampIdList>,
    user_stamp_list: Data<Mutex<UserStampList>>,
) -> impl Responder {
    // 유저의 쿠키 확인
    let ip = get_client_ip(&req);
    let cookie = req.cookie("user_id");

    // 쿠키가 없을 경우 임시 리다이렉션 반환
    if cookie.is_none() {
        warn!("⚠️ [ACCESS_DENIED] [IP:{}] Unauthenticated access attempt to stamp.", ip);
        return Redirect::to(format!("/stamp/?random={}", Uuid::new_v4())).temporary();
    }

    // 쿠키가 있을 경우 쿠키 값을 가져옴
    let student_id = cookie.unwrap().value().to_string();
    let users_guard = user_list.lock().unwrap(); // Lock 범위 최소화 권장

    // 유저 확인
    if !users_guard.users.contains_key(&student_id) {
        warn!("🚨 [FORGED_COOKIE] [UID:{}] [IP:{}] Invalid cookie detected.", student_id, ip);
        return Redirect::to(format!("/stamp/?random={}", Uuid::new_v4())).temporary();
    }

    // UA 검증 (보안 로그)
    let user = users_guard.users.get(&student_id).unwrap();
    let current_ua = get_user_agent(&req);
    let ua_check = check_ua_consistency(&current_ua, &user.user_agent);

    // UA가 다르면 경고, 같으면 디버그 수준 (너무 시끄러울 수 있으므로)
    if ua_check.starts_with("MISMATCH") {
        warn!("🕵️ [SUSPICIOUS_UA] [UID:{}] [IP:{}] [UA_Status:{}] User Agent changed since login.", student_id, ip, ua_check);
    }

    let stamp_id = req.query_string().split("s=").nth(1).unwrap_or_default().to_string();

    // 유효한 스템프 ID인 경우 유저의 스템프 정보 갱신
    if stamp_id_list.stamp_id_list.contains_key(&stamp_id) {
        // 로그 출력: 유저 ID 및 스템프 ID 정보 출력
        info!(
            "👀 [STAMP_VIEW] [UID:{}] [Name:{}] [StampID:{}] [IP:{}] User viewing stamp page.",
            student_id, user.user_name, stamp_id, ip
        );

        // Mutex를 사용하여 유저의 스템프 정보 갱신
        {
            let mut user_stamp_list = user_stamp_list.lock().unwrap();
            user_stamp_list
                .user_stamp_list
                .insert(student_id.clone(), stamp_id.clone());
            // user_stamp_list는 여기서 더 이상 사용되지 않으므로 이 지점에서 뮤텍스 해제
        }
    }

    // 아무 의미없는 랜덤 주소로 리다이렉션
    Redirect::to(format!("/stamp/?random={}", Uuid::new_v4())).temporary()
}

/// 스템프 찍기 요청을 처리하는 비동기 함수입니다. 유저의 쿠키를 확인하고, 해당 유저의 스템프를 가져온 후,
/// 유저의 스템프를 갱신하고 형식화된 HTML을 반환합니다.
///
/// # Arguments
///
/// * `req` - `HttpRequest` 객체로, 요청에 대한 정보를 포함합니다.
/// * `user_stamp_list` - 유저의 스템프 정보를 관리하는 `UserStampList`에 대한 `Data<Mutex<UserStampList>>`입니다.
///
/// # Returns
///
/// 유저의 스템프를 성공적으로 찍은 경우, 해당 스템프를 형식화한 HTML과 함께 200 OK 응답이 반환됩니다.
/// 유저의 쿠키가 없거나 스템프 url이 틀린 경우, 스템프를 찾지 못한 경우 401 Unauthorized 또는 404 Not Found 응답이 반환됩니다.
///
/// # Example
///
/// ```rust
/// #[actix_web::main]
/// async fn main() {
///     // Actix-web 앱 생성 및 라우터 등록
///     let app = App::new().service(handle_stamp);
///     // HTTP 서버 생성 및 실행
///     HttpServer::new(|| {
///         app.clone()
///     })
///     .bind("127.0.0.1:8080").unwrap()
///     .run()
///     .await
///     .unwrap();
/// }
/// ```
async fn handle_stamp(
    req: HttpRequest,
    user_list: Data<Mutex<UserList>>,
    user_stamp_list: Data<Mutex<UserStampList>>,
    user_history: Data<Mutex<StampHistory>>,
) -> impl Responder {
    let ip = get_client_ip(&req);
    // 1. 사용자 인증 (쿠키에서 user_id 가져오기)
    let student_id = match req.cookie("user_id") {
        Some(cookie) => cookie.value().to_string(),
        None => {
            warn!("⚠️ [STAMP_FAIL] [IP:{}] No cookie presented for stamping.", ip);
            return handle_401().await;
        }
    };

    // 2. 쿠키의 user_id가 실제 사용자인지 검증
    let users = user_list.lock().unwrap();
    if !users.users.contains_key(&student_id) {
        warn!("🚫 [STAMP_REJECT] [UID:{}] [IP:{}] Invalid user_id in cookie.", student_id, ip);
        return handle_401().await;
    }

    // 유저의 스템프 정보를 복사
    let su_list = user_stamp_list.lock().unwrap().user_stamp_list.clone();

    // 유저의 스템프 정보를 확인하고 찾은 경우 갱신 및 형식화된 HTML 반환
    if !su_list.contains_key(&student_id) {
        warn!("🚫 [STAMP_REJECT] [UID:{}] [IP:{}] User attempted unauthorized stamp access (flow error).", student_id, ip);
        return handle_401().await;
    }

    let stamp_id = su_list.get(&student_id).unwrap().clone();
    user_stamp_list.lock().unwrap().user_stamp_list.remove(&student_id);
    
    let timestamp = chrono::prelude::Utc::now().to_string();

    // 유저 정보 가져오기 (로그용)
    let (user_name, stored_ua) = users.users.get(&student_id)
        .map_or(("Unknown".to_string(), "".to_string()), |u| (u.user_name.clone(), u.user_agent.clone()));

    // UA 재확인
    let current_ua = get_user_agent(&req);
    let ua_status = check_ua_consistency(&current_ua, &stored_ua);

    // ... (히스토리 저장 로직)
    user_history.lock().unwrap().stamp_history.get_mut(&stamp_id).unwrap().extend(vec![StampUserInfo {
        student_id: student_id.to_string(),
        user_name: user_name.clone(),
        timestamp,
    }]);

    // [변경] 스탬프 완료 로그 (성공 여부 명확히)
    info!(
        "✅ [STAMP_COMPLETE] [UID:{}] [Name:{}] [StampID:{}] [IP:{}] [UA:{}] Stamp process finished.",
        student_id, user_name, stamp_id, ip, ua_status
    );

    if !stamp_id.is_empty() {
        return HttpResponse::Ok()
            .insert_header(("Cache-Control", "no-cache"))
            .body(format_file(&stamp_id).await);
    }

    warn!("❓ [STAMP_INVALID] [UID:{}] Invalid stamp ID processing.", student_id);
    handle_404().await
}

async fn handle_generate_otp(
    req: HttpRequest,
    otp_store: Data<Mutex<OtpStore>>,
    user_list: Data<Mutex<UserList>>,
    user_success_history: Data<Mutex<UserSuccessHistory>>,
) -> impl Responder {
    // 1. 사용자 인증 (쿠키에서 user_id 가져오기)
    let student_id = match req.cookie("user_id") {
        Some(cookie) => cookie.value().to_string(),
        None => {
            warn!("OTP generation failed: User not authenticated (no cookie).");
            return HttpResponse::Unauthorized().finish();
        }
    };

    // 2. 쿠키의 user_id가 실제 사용자인지 검증
    let users = user_list.lock().unwrap();
    if !users.users.contains_key(&student_id) {
        warn!(
            "OTP generation failed: Invalid user_id '{}' in cookie.",
            student_id
        );
        return HttpResponse::Unauthorized().finish();
    }

    // 3. 이전 성공 이력 조회
    let success_history = user_success_history.lock().unwrap();
    let previous_success = success_history.get(&student_id).cloned();

    // 4. 6자리 랜덤 OTP 생성
    const OTP_VALIDITY_SECONDS: i64 = 60;
    let mut rng = rand::thread_rng();
    let otp = format!("{:06}", rng.gen_range(0..1_000_000));

    // 5. OTP 데이터 생성 및 저장
    let generation_time = chrono::Utc::now().timestamp();
    let otp_auth = OtpAuth {
        student_id: student_id.clone(),
        generation_time,
        expiration_time: generation_time + OTP_VALIDITY_SECONDS,
    };

    let mut store = otp_store.lock().unwrap();
    store.insert(otp.clone(), otp_auth);

    info!("Generated OTP {} for student_id: {}", otp, student_id);

    // 6. 새로운 형식의 JSON으로 응답
    HttpResponse::Ok().json(GenerateOtpResponse {
        new_otp: otp,
        previous_success,
    })
}

#[derive(Serialize, Deserialize, Debug, Clone)]
struct SUC {
    status: String
}

async fn handle_issue_stamp(
    payload: Json<KioskStampRequest>,
    user_list: Data<Mutex<UserList>>,
    stamp_id_list: Data<StampIdList>,
    user_history: Data<Mutex<StampHistory>>,
    otp_store: Data<Mutex<OtpStore>>,
    user_success_history: Data<Mutex<UserSuccessHistory>>,
) -> impl Responder {
    // 1. OTP 조회 및 제거
    let mut store = otp_store.lock().unwrap();
    let otp_auth = match store.remove(&payload.otp) {
        Some(auth) => auth,
        None => {
            warn!("Invalid OTP '{}' used.", payload.otp);
            return HttpResponse::BadRequest().body("Invalid or already used OTP.");
        }
    };

    // 2. 타임스탬프 유효성 검사
    let current_timestamp = chrono::Utc::now().timestamp();
    if current_timestamp > otp_auth.expiration_time {
        warn!(
            "Expired OTP '{}' used for student_id: {}. (Expired at: {})",
            payload.otp, otp_auth.student_id, otp_auth.expiration_time
        );
        return HttpResponse::BadRequest().body("OTP has expired.");
    }

    // 3. 사용자 및 스탬프 유효성 검사
    let users = user_list.lock().unwrap();
    let user = match users.users.get(&otp_auth.student_id) {
        Some(u) => u,
        None => {
            // 이 경우는 OTP가 발급되었으나 그 사이 유저가 삭제된 극히 드문 케이스
            warn!("Invalid student_id '{}' from valid OTP '{}'.", otp_auth.student_id, payload.otp);
            return HttpResponse::BadRequest().body("Invalid user.");
        }
    };

    if !stamp_id_list.stamp_id_list.contains_key(&payload.stamp_id) {
        warn!("Invalid stamp_id '{}' from kiosk.", payload.stamp_id);
        return HttpResponse::BadRequest().body("Invalid stamp.");
    }

    // 4. 스탬프 발급
    let mut history = user_history.lock().unwrap();
    let stamp_log = history.stamp_history.entry(payload.stamp_id.clone()).or_insert_with(Vec::new);

    let user_info = StampUserInfo {
        student_id: user.student_id.clone(),
        user_name: user.user_name.clone(),
        timestamp: chrono::Utc::now().to_string(),
    };

    stamp_log.push(user_info);

    info!("Issued stamp '{}' to student_id '{}' via OTP", payload.stamp_id, user.student_id);

    // 5. 성공 이력 저장
    let mut success_history = user_success_history.lock().unwrap();
    let success_info = SuccessfulOtpInfo {
        otp: payload.otp.clone(),
        stamp_id: payload.stamp_id.clone(),
        timestamp: current_timestamp,
    };
    success_history.insert(user.student_id.clone(), success_info);


    HttpResponse::Ok().json(SUC {status:String::from("success")})
}

async fn handle_admin(
    command: Json<Command>,
    stamp_history: Data<Mutex<StampHistory>>,
    user_list: Data<Mutex<UserList>>,
    req: HttpRequest,
) -> HttpResponse {
    let ip = req.peer_addr().unwrap().ip();

    let mut cmd_output = Command {
        command: "".to_string(),
        output: "Command not found".to_string(),
    };

    if !ip.is_loopback() {
        warn!(
            "{}",
            format!(
                "{} Unauthorized access to the Admin page has been identified in .",
                ip
            )
        );
        return handle_401().await;
    }

    if command.command == "stamp status".to_string() {
        info!(
            "{}",
            format!("Database lookup request : {}", command.command,)
        );
        save_file("stamp_status", stamp_history.lock().unwrap().clone()).unwrap();
        cmd_output.output = format!("{:?}", stamp_history.lock().unwrap().clone())
    } else if command.command == "save all".to_string() {
        save_file("stamp_status", stamp_history.lock().unwrap().clone()).unwrap();
        save_file("user_status", user_list.lock().unwrap().clone()).unwrap();
        cmd_output.output = "All databases saved".to_string()
    }

    HttpResponse::Ok().json(cmd_output)
}

fn save_file<T: serde::Serialize>(file_name: &str, data: T) -> Result<bool, bool> {
    match File::create(format!("resources/database/{}.json", file_name)) {
        Ok(mut file) => match serde_json::to_writer(file, &data) {
            Ok(_) => {
                info!("Database save complete");
                return Ok(true);
            }
            Err(_) => {
                error!("Database save Failed");
                return Err(false);
            }
        },
        Err(_) => {
            error!("Database save Failed");
            Err(false)
        }
    }
}

async fn handle_login(
    req: HttpRequest,
    payload: Json<LoginRequest>,
    user_list: Data<Mutex<UserList>>,
) -> HttpResponse {
    let mut users = user_list.lock().unwrap();
    let ip = get_client_ip(&req);
    let current_ua = get_user_agent(&req);
    let combined_string = format!(
        "{}:{}",
        payload.user, payload.password
    );
    let student_id = Uuid::new_v5(&NAMESPACE_UUID, combined_string.as_bytes()).to_string();

    match users.users.get(&student_id) {
        // --- User Exists -> Login ---
        Some(existing_user) => {
            let ua_status = check_ua_consistency(&current_ua, &existing_user.user_agent);

            info!(
                "🟢 [LOGIN_SUCCESS] [UID:{}] [Name:{}] [IP:{}] [UA:{}] User logged in.",
                existing_user.student_id, existing_user.user_name, ip, ua_status
            );

            let response_user = LoginResponse {
                user_id: existing_user.student_id.clone(),
                user_name: existing_user.user_name.clone(),
            };
            let cookie_user_name = Cookie::build("user_name", existing_user.user_name.clone())
                .path("/")
                .finish();
            let cookie_user_id = Cookie::build("user_id", existing_user.student_id.clone())
                .path("/")
                .finish();

            HttpResponse::Ok().cookie(cookie_user_name).cookie(cookie_user_id).json(response_user)
        }
        // --- User Not Found -> Register ---
        None => {
            info!(
                "🆕 [REGISTER_NEW] [UID (Gen):{}] [Name:{}] [IP:{}] [UA:New] New user registration.",
                student_id, payload.user, ip
            );

            // ... (기존 비밀번호 해시 및 유저 생성 로직)
            let password_hash = match bcrypt::hash(&payload.password, bcrypt::DEFAULT_COST) {
                Ok(h) => h,
                Err(e) => {
                    error!("❌ [REGISTER_FAIL] [IP:{}] Error hashing password: {}", ip, e);
                    return HttpResponse::InternalServerError().finish();
                }
            };

            let new_user = User {
                student_id: student_id.clone(),
                user_name: payload.user.clone(),
                password_hash,
                user_agent: current_ua, // 등록 시 UA 저장
            };

            users.users.insert(student_id.clone(), new_user.clone());

            let response_user = LoginResponse {
                user_id: new_user.student_id,
                user_name: new_user.user_name,
            };

            let cookie_user_name = Cookie::build("user_name", response_user.user_name.clone())
                .path("/")
                .finish();
            let cookie_user_id = Cookie::build("user_id", student_id.clone())
                .path("/")
                .finish();

            info!("🆕 [COOKIE] user_name: {}, user_id: {}", cookie_user_name.to_string(), cookie_user_id.to_string());

            HttpResponse::Ok().cookie(cookie_user_name).cookie(cookie_user_id).json(response_user)
        }
    }
}

/// JSON 형식의 스탬프 정보를 읽어와서 `StampIdList` 구조체로 변환하는 함수입니다.
///
/// # Returns
///
/// 성공적으로 파일을 열고 JSON을 읽어온 경우, 해당 정보를 담은 `StampIdList`가 반환됩니다.
/// 파일이 존재하지 않거나 JSON 파싱에 실패한 경우 빈 `StampIdList`가 반환됩니다.
///
/// # Example
///
/// ```rust
/// #[tokio::main]
/// async fn main() {
///     let stamp_id_list = parse_json();
///     println!("Loaded Stamp ID List: {:?}", stamp_id_list);
/// }
/// ```
fn stamp_db() -> StampIdList {
    // 파일 열기
    let stamp_list: StampList = match File::open("resources/api/stampList.json") {
        Ok(mut file) => {
            // 파일 내용을 읽어 문자열로 변환
            let mut file_content = String::new();
            file.read_to_string(&mut file_content)
                .expect("Failed to read file content");

            info!("Stamp Database load complete");
            // JSON 문자열을 파싱하여 StampList 구조체로 변환
            from_str(&file_content).expect("Failed to parse JSON")
        },
        Err(_) => {
            error!("Stamp Database load Failed");
            StampList { stampList: HashSet::new()}
        }
    };

    // StampList에서 스탬프 ID 리스트를 추출하여 StampIdList 구조체로 변환
    if stamp_list.stampList.is_empty() {
        error!("Stamp DataBase load Failed");
        panic_any("Stamp DataBase load Failed");
    }

    StampIdList {
        stamp_id_list: stamp_list
            .stampList
            .iter()
            .map(|stamp| (stamp.stampId.clone(), stamp.clone()))
            .collect(),
    }
}

fn stamp_history_db(stamp_id_list: StampIdList) -> StampHistory {
    // 파일 열기
    let stamp_history: StampHistory = match File::open("resources/database/stamp_status.json") {
        Ok(mut file) => {
            // 파일 내용을 읽어 문자열로 변환
            let mut file_content = String::new();
            file.read_to_string(&mut file_content)
                .expect("Failed to read file content");

            info!("Stamp History Database load complete");
            // JSON 문자열을 파싱하여 StampList 구조체로 변환
            from_str(&file_content).expect("Failed to parse JSON")
        }
        Err(_) => {
            warn!("Stamp History load Failed");
            StampHistory {
                stamp_history: stamp_history(stamp_id_list),
            }
        }
    };

    // 로그 출력: 데이터베이스 로드 완료 메시지

    // 최종적으로 구성된 StampIdList 반환
    stamp_history
}

fn user_list_db() -> UserList {
    // 파일 열기
    let user_list: UserList = match File::open("resources/database/user_status.json") {
        Ok(mut file) => {
            // 파일 내용을 읽어 문자열로 변환
            let mut file_content = String::new();
            file.read_to_string(&mut file_content)
                .expect("Failed to read file content");

            info!("User List Database load complete");
            // JSON 문자열을 파싱하여 StampList 구조체로 변환
            from_str(&file_content).expect("Failed to parse JSON")
        }
        Err(_) => {
            warn!("User List Database load Failed");
            UserList {
                users: Default::default(),
            }
        }
    };

    user_list
}

/// 주어진 스탬프 ID를 사용하여 HTML 파일을 형식화하는 비동기 함수입니다.
///
/// # Arguments
///
/// * `stamp_id` - 형식화에 사용될 스탬프 ID입니다.
///
/// # Returns
///
/// 성공적으로 HTML 파일을 읽고 형식화한 경우 해당 파일의 내용을 반환하며,
/// 실패한 경우 "Fail to format" 문자열을 반환합니다.
///
/// # Example
///
/// ```rust
/// #[tokio::main]
/// async fn main() {
///     let stamp_id = "123456";
///     let formatted_html = format_file(stamp_id).await;
///     println!("Formatted HTML: {}", formatted_html);
/// }
/// ```
async fn format_file(stamp_id: &str) -> String {
    // path 함수를 사용하여 'check.html' 파일 읽기 시도
    match path("html", "check.html").await {
        Ok(file) => file.replace("%STAMP_ID%", stamp_id), // 파일 내용에서 '%STAMP_ID%'를 주어진 스탬프 ID로 대체
        Err(_) => "Fail to format".to_string(),           // 파일 읽기 실패 시 "Fail to format" 반환
    }
}

/// HTML 파일을 처리하는 핸들러 함수입니다. 요청된 파일을 읽어와 HTTP 응답으로 반환합니다.
///
/// # Arguments
///
/// * `req` - `HttpRequest` 객체로, 요청에 대한 정보를 포함합니다.
///
/// # Returns
///
/// `HttpResponse` 객체로, 성공적으로 파일을 읽은 경우 해당 파일의 내용을 담아 반환하고, 실패한 경우 404 응답을 반환합니다.
///
/// # Example
///
/// ```rust
/// #[actix_web::main]
/// async fn main() {
///     // Actix-web 앱 생성 및 라우터 등록
///     let app = App::new().service(handle_html);
///     // HTTP 서버 생성 및 실행
///     HttpServer::new(|| {
///         app.clone()
///     })
///     .bind("127.0.0.1:8080").unwrap()
///     .run()
///     .await
///     .unwrap();
/// }
/// ```
async fn handle_html(req: HttpRequest) -> impl Responder {
    let file_query = req.match_info().query("file");
    let ip = get_client_ip(&req);

    // [변경] HTML 요청도 DEBUG 레벨로 내림
    debug!("[HTML Request] [IP: {}] {}", ip, file_query);
    // 요청된 파일 이름을 '.'을 기준으로 분리
    let split_str: Vec<&str> = req.match_info().query("file").split('.').collect();

    // 초기화되지 않은 상태에서 formatted_file 변수를 선언
    let formatted_file: String;
    let file: &str;

    // 파일 이름이 확장자 없이 제공된 경우 '.html'을 추가하여 파일명을 형식화
    if split_str.len() == 1 {
        formatted_file = format!("{}.html", split_str[0]);
        file = &formatted_file;
    } else {
        // 확장자가 포함된 경우 기존 파일명 사용
        file = req.match_info().query("file");
    }

    // path 함수를 사용하여 HTML 파일 읽기 시도
    match path("html", file).await {
        Ok(result) => {
            // 파일이 존재하지 않는 경우 404 응답 반환
            if result.contains("File not found") {
                warn!("[HTML Not Found] [IP: {}] {}", ip, file); // 404는 경고
                handle_404().await
            } else {
                // 파일이 성공적으로 읽혔을 경우 200 OK 응답과 파일 내용 반환
                HttpResponse::Ok().body(result)
            }
        }
        Err(_) => handle_404().await, // 파일 읽기 실패 시 404 응답 반환
    }
}

/// 지정된 폴더와 파일 이름을 사용하여 파일의 경로를 설정하고, `read_file` 함수를 사용하여 파일을 비동기적으로 읽어옵니다.
///
/// # Arguments
///
/// * `folder` - 파일이 위치한 폴더의 이름입니다.
/// * `file` - 읽어올 파일의 이름입니다.
///
/// # Returns
///
/// 읽은 파일이 텍스트 일경우 `Ok(String)`이 반환되며, 바이너리 파일인 경우 `Err(Vec<u8>)`이 반환됩니다.
///
/// # Example
///
/// ```
/// #[get("/")]
/// async fn index() -> impl Responder {
///     match path("html", "index.html").await {
///         Ok(v) => HttpResponse::Ok().body(v),
///         Err(_) => handle_404().await,
///     }
/// }
/// ```
async fn path(folder: &str, file: &str) -> Result<String, Vec<u8>> {
    // 현재 실행 파일 경로를 얻고, 오류가 발생하면 기본값을 사용합니다.
    let file_path = env::current_exe()
        .map(|exe_path| {
            exe_path.parent().map_or(Default::default(), |exe_dir| {
                exe_dir.join(Path::new(&format!("resources/{}/{}", folder, file)))
            })
        })
        .unwrap_or_else(|e| {
            // eprintln!("Failed to get the current executable path: {}", e);
            Default::default()
        });

    // 파일 경로에서 읽어온 결과를 반환
    match read_file(file_path.as_path()).await {
        Ok(v) => Ok(v),
        Err(e) => Err(e),
    }
}

/// 지정된 경로의 파일을 읽어 문자열 또는 이진 데이터로 반환하는 비동기 함수입니다.
///
/// # Arguments
///
/// * `path` - 파일을 나타내는 경로입니다.
///
/// # Returns
///
/// 읽은 파일이 텍스트 일경우 `Ok(String)`이 반환되며, 바이너리 파일인 경우 `Err(Vec<u8>)`이 반환됩니다.
///
/// # Examples
///
/// ```
/// match read_file(file_path.as_path()).await {
///     Ok(v) => Ok(v),
///     Err(e) => Err(e),
/// }
/// ```
async fn read_file(path: &Path) -> Result<String, Vec<u8>> {
    // 이진 파일 확장자 목록
    let binary_file_list: Vec<&str> = vec!["ico", "png", "webp", "ttf", "woff2", "woff"];

    // 파일 내용을 저장할 벡터
    let mut binary_contents = Vec::new();
    let mut str_contents = String::new();

    // 파일을 열고 오류를 문자열로 변환하여 반환
    File::open(path)
        .map_err(|e| {
            // println!("파일 {:?} 의 경로를 찾을수 없습니다.", path);
            str_contents = "File not found".to_string()
        })
        .and_then(|mut file| {
            // ? 연산자를 사용하여 오류가 발생하면 조기에 반환
            file.read_to_end(&mut binary_contents)
                .expect("파일 읽기 실패");
            Ok::<String, _>(format!("파일 {:?} 읽기 실패", path))
        })
        .ok(); // 결과가 이미 로깅되었으므로 무시합니다.

    // 파일 확장자를 추출하고, 이진 파일 목록에 있는 경우 에러를 반환
    let split_extension: Vec<&str> = path.to_str().unwrap_or_default().split('.').collect();

    if let Some(&list_extension) = split_extension.last() {
        if binary_file_list.contains(&list_extension) {
            return Err(binary_contents);
        } else if &"svg" == &list_extension {
            svg::open(path, &mut str_contents).unwrap();
            return Ok(str_contents);
        }
    }

    // 이진 데이터를 문자열로 변환하고, 변환에 실패하면 에러를 반환
    String::from_utf8(binary_contents.clone()).map_err(|_| binary_contents)
}

/// 커맨드라인 인수를 파싱하여 서버 바인딩 정보를 추출합니다.
///
/// # Arguments
///
/// * `cmd` - 커맨드라인 인수를 나타내는 문자열 벡터입니다.
/// * `cmd_len` - 커맨드라인 인수 벡터의 길이입니다.
///
/// # Returns
///
/// 파싱된 서버 바인딩 정보(address, port, protocol)를 담고 있는 `AddressInfo` 구조체입니다.
///
/// # Example
///
/// ```
/// let args = vec![
///     "프로그램_이름".to_string(),
///     "-a".to_string(), "127.0.0.1".to_string(),
///     "-p".to_string(), "8080".to_string(),
///     "--protocol".to_string(), "https".to_string(),
/// ];
/// let address_info = handle_args(args, 7);
/// assert_eq!(address_info.address, "127.0.0.1");
/// assert_eq!(address_info.port, 8080);
/// assert_eq!(address_info.protocol, "https");
/// ```
fn handle_args(cmd: Vec<String>, cmd_len: usize) -> AddressInfo {
    // 커맨드라인 옵션과 값을 저장할 HashMap
    let mut cmd_line = HashMap::new();

    // 주소, 포트, 프로토콜의 기본값
    let mut address = "127.0.0.1".to_string();
    let mut port = 80;
    let mut protocol = "http".to_string();

    // 프로그램 이름을 제외하고 커맨드라인 인수를 반복
    let args_iter = cmd
        .iter()
        .skip(1)
        .step_by(2)
        .zip(cmd.iter().skip(2).step_by(2));

    // 커맨드라인 옵션과 값을 cmd_line HashMap에 채움
    for (key, value) in args_iter {
        cmd_line.insert(&key[..], value);
    }

    // 커맨드라인 인수에서 주소가 제공되면 업데이트
    if let Some(addr) = cmd_line.get("-a") {
        address = addr.to_string();
    }

    // 커맨드라인 인수에서 포트가 제공되면 업데이트
    if let Some(port_str) = cmd_line.get("-p") {
        if let Ok(p) = port_str.parse() {
            port = p;
        }
    }

    // 커맨드라인 인수에서 프로토콜이 제공되면 업데이트
    if let Some(proto) = cmd_line.get("--protocol") {
        protocol = proto.to_string();
    }

    // 파싱된 정보를 담은 AddressInfo 구조체를 생성하고 반환
    AddressInfo {
        address,
        port,
        protocol,
    }
}

fn stamp_history(stamp_id_list: StampIdList) -> HashMap<String, Vec<StampUserInfo>> {
    let mut stamp_history = HashMap::new();

    for (stamp_id, stamp) in stamp_id_list.stamp_id_list.iter() {
        stamp_history.insert(stamp_id.clone(), Vec::new()); // Note: Use clone() to get a String, assuming stamp_id is a String
    }

    stamp_history
}

// Actix-web 서버 구성 및 설정
async fn run(address: AddressInfo) -> std::io::Result<()> {
    // 유저 리스트 초기화
    let user_list: Data<Mutex<UserList>> = Data::new(Mutex::new(user_list_db()));

    // 데이터베이스 초기화
    let stamp_list: StampIdList = stamp_db();

    // 유저 스템프 요청 초기화
    let user_stamp_list: Data<Mutex<UserStampList>> = Data::new(Mutex::new(UserStampList {
        user_stamp_list: HashMap::new(),
    }));

    let move_address = address.clone();

    let user_history: Data<Mutex<StampHistory>> =
        Data::new(Mutex::new(stamp_history_db(stamp_list.clone())));

    // OTP 저장소 초기화
    let otp_store: Data<Mutex<OtpStore>> = Data::new(Mutex::new(OtpStore::new()));

    // 유저의 마지막 OTP 성공 이력 저장소 초기화
    let user_success_history: Data<Mutex<UserSuccessHistory>> =
        Data::new(Mutex::new(UserSuccessHistory::new()));

    HttpServer::new(move || {
        App::new()
            .wrap(
                Logger::new(r#"%a "%r" %s %b "%{Referer}i" "%{User-Agent}i" %Dms"#)
                    .exclude("/favicon.ico") // 예시
                    // 주의: /{folder}/{file} 같은 동적 라우트는 exclude로 잡기 어렵습니다.
                    // 따라서 미들웨어는 '시스템 로그'용으로 두고,
                    // 우리가 작성한 '비즈니스 로그(로그인, 스탬프)'를 중심으로 모니터링하는 것이 좋습니다.
                    // 만약 파일 로그가 너무 많다면, 아래와 같이 exclude_regex를 시도할 수 있습니다.
                    .exclude_regex(r"^/css/.*")
                    .exclude_regex(r"^/scripts/.*")
                    .exclude_regex(r"^/fonts/.*")
                    .exclude_regex(r"^/images/.*")
                    .exclude_regex(r"^/map/.*")
                    .exclude_regex(r"^/sounds/.*")
                    .exclude_regex(r"^/videos/.*")
                    .exclude_regex(r"^/api/.*")
            )
            .app_data(Data::new(stamp_list.clone())) // 전역변수 선언
            .app_data(Data::new(move_address.clone())) // 전역변수 선언
            .app_data(Data::clone(&user_list)) // 전역변수 선언
            .app_data(Data::clone(&user_stamp_list)) // 전역변수 선언
            .app_data(Data::clone(&user_history)) // 전역변수 선언
            .app_data(Data::clone(&otp_store)) // OTP 저장소 전역 변수 선언
            .app_data(Data::clone(&user_success_history)) // 마지막 OTP 성공 이력 저장소 전역 변수 선언
            .route("/", get().to(index)) // 인덱스 요청 처리
            .service(resource("/login").route(post().to(handle_login))) // 로그인 요청 처리
            .service(resource("/admin").route(post().to(handle_admin)))
            .route("/otp/generate", get().to(handle_generate_otp)) // OTP 생성
            .route("/stamp/issue", post().to(handle_issue_stamp))     // QR 스탬프 발급
            .route("/check", get().to(handle_check)) // 스템프 리다이렉션 처리
            .route("/stamp", get().to(handle_stamp)) // 스템프 찍기 처리
            .route("/{file}", get().to(handle_html)) // HTML 요청 처리
            .route("/{folder}/{file}", get().to(handle_req)) // 일반 파일 요청 처리
            .default_service(route().to(handle_404)) // 만약 위의 처리 항목 중 해당되는게 없으면 404 응답 전송
    })
    .bind((address.address.as_str(), address.port))? // 서버 바인딩
    .run()
    .await
}

// fn auto_save(delay: u64) {
//     info!(
//         "{}",
//         format!("Autosave is enabled. Auto-save interval: {} min", delay)
//     );
//
//     loop {
//         thread::sleep(Duration::from_secs(delay * 60));
//         info!("Auto-saving...");
//         let response = Client::new()
//             .post("http://127.0.0.1:80/admin")
//             .json(&Command {
//                 command: "save all".to_string(),
//                 output: "".to_string(),
//             })
//             .header("Content-Type", "application/json")
//             .send();
//         info!("Auto-save completed")
//     }
// }

// async fn run_auto_save(delay: u64, url: &str, client: Client, cmd: Command) -> bool {
//     let response = client
//         .post(url)
//         .json(&cmd)
//         .header("Content-Type", "application/json")
//         .send()
//         .await;
//
//     // 응답 상태 코드 확인
//     response.unwrap().status() == StatusCode::OK
// }
// 메인 함수
#[actix_web::main]
async fn main() {
    // log4rs 로거 초기화
    log4rs::init_file("log4rs.yaml", Default::default()).expect("Failed to initialize logger");
    // 실행 인수 초기화
    let args: Vec<String> = env::args().collect();
    // 서버 바인딩 정보 초기화
    let address_info = handle_args(args.clone(), args.len());

    // 서버 시작 로그 출력
    info!(
        "{}",
        format!(
            "[ version ]: 0.1.2 | Rust {protocol} Actix-web server started at {protocol}://{address}:{port}",
            protocol = address_info.protocol,
            address = address_info.address,
            port = address_info.port
        )
    );

    // let handle = thread::spawn(|| auto_save(1));
    run(address_info).await.unwrap();
}
