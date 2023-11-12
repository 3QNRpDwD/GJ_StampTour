//
//  root.js
//  GJ_StampTour
//
//  Created by Js Na on 2023/03/20.
//  Copyright © 2023 Js Na, All rights reserved.
//
function eById(id) {
    return document.getElementById(id);
}
function setCookie(name, value, exp) {
    var date = new Date();
    date.setTime(date.getTime() + exp * 24 * 60 * 60 * 1000);
    document.cookie = encodeURIComponent(name) + '=' + encodeURIComponent(value) + ';expires=' + date.toUTCString() + ';path=';
}
function getCookie(name) {
    var value = document.cookie.match('(^|;) ?' + name + '=([^;]*)(;|$)');
    return value ? value[2] : null;
}
function deleteCookie(name) {
    document.cookie = encodeURIComponent(name) + '=; expires=Thu, 01 JAN 1999 00:00:10 GMT';
}
function getParameter(name) {
    if (name = (new RegExp('[?&]' + encodeURIComponent(name) + '=([^&]*)')).exec(location.search))
        return decodeURIComponent(name[1]);
}

function init() {
    if (userSignedIn) {
        setStampView();
        getStampList();
        enableCookieUpdate();
    } else {
        setLoginView();
    }
}
function enableCookieUpdate() {
    setInterval(function () {
        let stampJSON = getCookie('localStamp');
        if (stampJSON != null) {
            stampJSON = decodeURIComponent(stampJSON);
            let stampList = JSON.parse(stampJSON);
            console.log(stampList);
            for (let i = 0; i < stampList.length; i++) {
                let stampData = stampList[i];
                let stampElement = eById(stampData);
                if (stampElement != null) {
                    stampElement.classList.add("checked");
                }
            }
        }
    }, 1000);
}

function enableMapZoom(mapElement) {
    var cityMinZoom = 0.6;
    if ('ontouchstart' in window || navigator.msMaxTouchPoints) {
        zoom = panzoom(mapElement, {
            bounds: true,
            boundsPadding: 0,
            maxZoom: 5,
            minZoom: cityMinZoom,
            zoomDoubleClickSpeed: 1,
            // svg 내부 버튼 처리. circle 바꾸면 될 듯.
            /*onTouch: (e) => {
                const targetElem = e.target
                if (targetElem.tagName === 'circle') {
                    return false
                } else {
                    e.preventDefault()
                }
            } */
        });
    } else {
        zoom = panzoom(mapElement, {
            bounds: true,
            boundsPadding: 0,
            maxZoom: 5,
            minZoom: cityMinZoom,
            zoomDoubleClickSpeed: 1,
        });
    }
}

function getClassroomList() {
    getJSON(`/api/classList.json`, function (err, data) {
        if (err != null) {
            alert("교실 목록 데이터를 불러오는 중 오류가 발생했습니다.");
            console.error(err);
        } else if (data !== null) {
            console.log(data);
            let classList = data.classList;
            console.log(classList);
            for (let i = 0; i < classList.length; i++) {
                let classData = classList[i];
                let classElement = eById(classData.classId);
                if (classElement != null) {
                    classElement.classList.add("active");
                    classElement.addEventListener("click", function () {
                        window.open(`/info/${classData.classId}`, "_self");
                    });
                }
            }
        }
    });
}

function getClassroomInfo(classroomId) {
    getJSON(`/api/classroom/${classroomId}.json`, function (err, data) {
        if (err != null) {
            alert(`교실(${classroomId}) 데이터를 불러오는 중 오류가 발생했습니다.`);
            console.error(err);
        } else if (data !== null) {
            return data;
        }
    });
}
function getStampList() {
    getJSON(`/api/stampList.json`, function (err, data) {
        if (err != null) {
            alert("스탬프 목록 데이터를 불러오는 중 오류가 발생했습니다.");
            console.error(err);
        } else if (data !== null) {
            console.log(data);
            let stampList = data.stampList;
            console.log(stampList);
            for (let i = 0; i < stampList.length; i++) {
                let stampData = stampList[i];
                let stampElement = document.createElement("div");
                stampElement.classList.add("stamp");
                stampElement.id = stampData.stampId;
                stampElement.innerHTML = `<img src="/images/check.svg"><h3 style="font-size: 0.9em">${stampData.stampName}</h3>`;
                eById("stampList").appendChild(stampElement);
            }
        }
    });
}
function getStampInfo(stampId) {
    getJSON(`/api/stamp/${stampId}.json`, function (err, data) {
        if (err != null) {
            alert(`스탬프(${stampId}) 데이터를 불러오는 중 오류가 발생했습니다.`);
            console.error(err);
        } else if (data !== null) {
            return data;
        }
    });
}
let userSignedIn = false;
function setStampView() {
    let stampView = eById("stampView");
    stampView.innerHTML = `<svg xmlns="http://www.w3.org/2000/svg" width="16" height="16" fill="currentColor" class="bi bi-chevron-compact-up" viewBox="0 0 16 16"><path fill-rule="evenodd" d="M7.776 5.553a.5.5 0 0 1 .448 0l6 3a.5.5 0 1 1-.448.894L8 6.56 2.224 9.447a.5.5 0 1 1-.448-.894l6-3z" /></svg><span class="stampViewTitle"><h1>스탬프투어</h1><a href="/guide.html">참여 방법 알아보기 ></a></span><div id="stampList" class="stampList"></div>`;
    eById("stampView").addEventListener("click", function () {
        eById("stampView").classList.toggle("open");
    });
}
function setLoginView() {
    let stampView = eById("stampView");
    // sign in with Kakao
    stampView.innerHTML = `<svg xmlns="http://www.w3.org/2000/svg" width="16" height="16" fill="currentColor" class="bi bi-chevron-compact-up" viewBox="0 0 16 16"><path fill-rule="evenodd" d="M7.776 5.553a.5.5 0 0 1 .448 0l6 3a.5.5 0 1 1-.448.894L8 6.56 2.224 9.447a.5.5 0 1 1-.448-.894l6-3z" /></svg><span class="stampViewTitle"><h1>스탬프투어</h1><a href="/guide.html">참여 방법 알아보기 ></a></span><div id="loginView" class="stampList">
    <div class="login">
        <h2>스탬프투어 참여를 위해 로그인이 필요합니다.</h2>
        <button id="loginButton" class="loginButton"><img src="/images/kakao_login_large_wide.png" alt="카카오 로그인" /></button>
    </div>`;
    eById("stampView").addEventListener("click", function () {
        eById("stampView").classList.toggle("open");
    });
}
