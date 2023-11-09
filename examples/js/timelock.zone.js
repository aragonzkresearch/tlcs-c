// adapted from https://github.com/ecies/rs-wasm/blob/master/example/index.js
// need to build with `wasm-pack build --target web`
// import init, * as ecies from "../pkg/ecies_wasm";
// check vite.config.js as well
import init, * as ecies from "ecies-wasm";
import {
    Base64
} from 'https://cdn.jsdelivr.net/npm/js-base64@3.7.5/base64.mjs';

init();
const encoder = new TextEncoder("ascii");
const decoder = new TextDecoder("ascii");

function fromHexString(hexString) {
    return Uint8Array.from(hexString.match(/.{1,2}/g).map((byte) => parseInt(byte, 16)));
}

function toBase64(s) {
    return Base64.fromUint8Array(s);
}

function fromBase64(s) {
    return Base64.toUint8Array(s);
}

function Enc() {

    const data = encoder.encode(document.getElementById('msg').value);
    const dateobj = new Date(document.getElementById('date').value);
    dateobj.setHours(0);
    dateobj.setMinutes(0);
    dateobj.setSeconds(1);
    const futuredate = dateobj.toLocaleString('en-US', {
        timezone: timelock_zone_timezone
    });
    const futuredateobj = new Date(futuredate);
    const month = futuredateobj.toLocaleString('default', {
        month: 'short'
    });
    const year = futuredateobj.getFullYear();
    var day = futuredateobj.getDate();
    var month2 = futuredateobj.getMonth();
    if (day < 10) {
        day = '0' + day;
    }

    month2++;
    if (month2 < 10) {
        month2 = '0' + month2;

    }

    const futuredatestr = day + month2 + year;
    // convert date into round Round
    //const date=new Date(month2+"/"+day+"/"+year);
    //var ut=parseInt((date.getTime() / 1000).toFixed(0));
    //var Round=parseInt((ut-DRAND_GENESIS_TIME)/DRAND_FREQUENCY).toFixed(0);
    const Round = DayToRound(futuredateobj);
    // TODO: we should use Round to retrieve the public key for round R and store it in pk
    // for the moment we assume that pk contains public key for round R

    //const pk=fromHexString("03E1AC8DB6A8D669BDD5753882A339273A864E113268156454F0107C25D0AC9ECD"); 
    //const pk=fromHexString("02972033bfc518338f7e94d93432a34a398e13ea4941c98b945a9aaff2b6b88088"); 
    //const pk=fromHexString("020d01c24bbb712130f5f20fbb2cbaabe82a605b67bf90d5363a1bfb8ce48d7ab2"); 
    getPublicKeyfromUrl(Round, "secp256k1").then(function(PK) {
        const pk = fromHexString(PK.substr(2));
        const encrypted = ecies.encrypt(pk, data);

        document.getElementById('enc').value = "This is an encrypted message to the future. To decrypt it you need to go to timelock.zone/enc.html, Go to the \"Decryption Page\", and paste the following string:\n" + futuredatestr + toBase64(encrypted);

        var copyText = document.getElementById("enc");

        // Select the text field
        copyText.select();
        copyText.setSelectionRange(0, 99999); // For mobile devices

        // Copy the text inside the text field
        navigator.clipboard.writeText(copyText.value);

        // Alert the copied text
        alert("Decryption instructions copied to clipboard");
    });
}

function Dec() {

    const daystr = document.getElementById('ct').value.slice(0, 2);
    const monthstr = document.getElementById('ct').value.slice(2, 4);
    const yearstr = document.getElementById('ct').value.slice(4, 8);
    const date = new Date(monthstr + "/" + daystr + "/" + yearstr);
    const localdate = new Date(date + timelock_zone_utc);
    const today = new Date();
    if (localdate.setHours(0, 0, 0, 1) > today.setHours(0, 0, 0, 1)) {
        alert("You must wait until " + localdate + " to decrypt");
        return;
    }
    // convert date into round Round 
    //var ut=parseInt((date.getTime() / 1000).toFixed(0))
    //var Round=parseInt((ut-DRAND_GENESIS_TIME)/DRAND_FREQUENCY).toFixed(0);
    const Round = DayToRound(date);
    getSecretKeyfromUrl(Round, "secp256k1").then(function(SK) {
        const sk = fromHexString(SK.substr(2));

        //const sk=fromHexString("9C8FC8D70B437C5545B71961DBBFDE3A3F59F53129E7B872FEA2E8BFC69EFBC7"); 
        //const sk=fromHexString("7ECF6611B6D4C2A94116FDB11DC8D87A703C43C2E9B1B34E594F4868B53B0E50"); 
        //const sk=fromHexString("16C74A8B2E3FEB225B7BABB703F51D5509837756C33501B48D58E52B78604C0B"); 
        const encrypted = document.getElementById('ct').value.slice(8);
        const ct = fromBase64(encrypted);
        const decrypted = ecies.decrypt(sk, ct);


        document.getElementById("dec").value = decoder.decode(decrypted);
        var copyText = document.getElementById("dec");


        navigator.clipboard.writeText(copyText.value);

        alert("Decrypted message copied to clipboard");
    });
}

function EncPage() {
    document.querySelector("#app").innerHTML = `
 <h1><div align="center"> Encrypt to the future</div></h1>
  <textarea rows="3" cols="50" id="msg">Type here a msg to encrypt...</textarea><br><br>
 <label for="date"> Choose a day in the future:    </label>
<input type="date" id="date" name="future" value="2023-12-13"  max="2024-12-31" /><br>
</span>
<br><br>

 <div> <button id="ok" class="block3">Encrypt</button></div><br>
  <textarea id="enc" name="encname" rows="9" cols="80" readonly>Encrypted message along instructions will be shown here...</textarea><br><br>
`;
    document.getElementById('date').min = new Date(new Date().getTime() - new Date().getTimezoneOffset() * 60000).toISOString().split("T")[0];
    document.getElementById('date').value = new Date(new Date().getTime() - new Date().getTimezoneOffset() * 60000).toISOString().split("T")[0];
    var tomorrow = new Date();
    var dd = tomorrow.getDate();
    var mm = tomorrow.getMonth();
    var yyyy = tomorrow.getFullYear() + 1;

    if (dd < 10) {
        dd = '0' + dd;
    }

    if (mm < 10) {
        mm = '0' + mm;
    }

    tomorrow = yyyy + '-' + mm + '-' + dd;
    document.getElementById("date").max = tomorrow;
    document.getElementById("ok").addEventListener("click", () => {
        Enc();
    });

}


function DecPage() {
    document.querySelector("#app").innerHTML = `
 <h1><div align="center"> Decrypt a message from the past</div></h1>
 <label for="ct"> Paste here the encrypted message: </label>
  <input type="text" id="ct" name="decname" value="Example: 11122023NCwyMTUsNjAsMTc2LDg2LDk2LDI0MCwxOTQsODEsMTQ3LDM5LDEzMiwyNTEsMjMyLDI0NiwyNCwyMjgsMTI4LDEwMCwyMTIsMzAsMTUzLDY1LDIyNiw4NSwxOTksMTMsMTIzLDk3LDI5LDE3NiwxMzYsMjU1LDU2LDE2LDEzMCwyNDIsMTcyLDEwOCwxNjUsMTIwLDE4MSwxNDMsNjMsMTMxLDI0Miw5Myw5MCwxMzAsMTQ3LDEzMyw3NCwxNjUsMTUyLDE2OCw3NSwxNTgsMTQ4LDE0MywxNDksMjMsMzcsMjM0LDE1OCwxMjMsMTA0LDE2NSw1NiwxMzksMTYsMTc3LDQzLDUsMTMyLDEyNCwyMjQsNjMsNDYsMjM5LDE3NywxMjQsODEsMjE5LDI1MSw5LDE3NywyOSwxNywyMjYsMTU5LDY0LDExOCwyMDgsMTk1LDQsNjksMTEzLDIwMiwyMzAsMTk0"></input><br><br><br><br>
 <div> <button id="decbtn" class="block3">Decrypt</button></div><br>
  <textarea id="dec" name="decname" value="" rows="5" cols="80" readonly>Decrypted msg will appear here...</textarea><br><br>
`;
    document.getElementById("decbtn").addEventListener("click", () => {
        Dec();
    });

}







document.getElementById("Encrypt").addEventListener("click", () => {
    EncPage();
});
document.getElementById("Decrypt").addEventListener("click", () => {
    DecPage();
});

window.addEventListener("error", (event) => {
    // catch all other errors
    console.error(event);
});