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
                stampElement.innerHTML = `<img src="/images/circle.svg"><img class="CheckMark" src="/images/check.svg"><span><h2>${stampData.stampName}</h2><p>${stampData.stampLocation}</p></span>`;
                eById("stampList").appendChild(stampElement);
            }
        }
    });
}