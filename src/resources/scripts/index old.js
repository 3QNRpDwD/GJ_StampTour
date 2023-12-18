//
//  index.js
//  GJ_StampTour
//
//  Created by Js Na on 2023/12/12.
//  Copyright © 2023 Js Na, All rights reserved.
//

let userSignedIn = true;
function init() {
    if (userSignedIn) {
        setStampView();
        getStampList();
        enableCookieUpdate();
    } else {
        setLoginView();
    }
}
function enableMapZoom(mapElement) {
    var cityMinZoom = 0.5;
    if ('ontouchstart' in window || navigator.msMaxTouchPoints) {
        zoom = panzoom(mapElement, {
            bounds: true,
            boundsPadding: -0.5,
            maxZoom: 5,
            minZoom: cityMinZoom,
            zoomDoubleClickSpeed: 1,
            // svg 내부 버튼 처리. circle 바꾸면 될 듯.
            onTouch: (e) => {
                const targetElem = e.target;
                if (targetElem.tagName === "g" || targetElem.tagName === "rect" || targetElem.tagName === "text") {
                    return false;
                } else {
                    e.preventDefault();
                }
            }
        });
    } else {
        zoom = panzoom(mapElement, {
            bounds: true,
            boundsPadding: -0.5,
            maxZoom: 5,
            minZoom: cityMinZoom,
            zoomDoubleClickSpeed: 1,
        });
    }
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