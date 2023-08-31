// adapted from https://github.com/ecies/rs-wasm/blob/master/example/index.js
// need to build with `wasm-pack build --target web`
// import init, * as ecies from "../pkg/ecies_wasm";
// check vite.config.js as well
import init, * as ecies from "ecies-wasm";

init();

const encoder = new TextEncoder();
const data = encoder.encode("This is a message coming from the past: ciao");

function fromHexString (hexString){
  return Uint8Array.from(hexString.match(/.{1,2}/g).map((byte) => parseInt(byte, 16)));
}

function checkOk() {
  const pk=fromHexString("03E1AC8DB6A8D669BDD5753882A339273A864E113268156454F0107C25D0AC9ECD"); // this string a the public key from the TLCS service for a round R

  const encrypted = ecies.encrypt(pk, data);
  // at a round R the TLCS service publishes the string "9C8FC8D70B437C5545B71961DBBFDE3A3F59F53129E7B872FEA2E8BFC69EFBC7"
  const sk=fromHexString("9C8FC8D70B437C5545B71961DBBFDE3A3F59F53129E7B872FEA2E8BFC69EFBC7"); 
  const decrypted = ecies.decrypt(sk, encrypted);

  const decoder = new TextDecoder();
  alert(`decrypted: ${decoder.decode(decrypted)}`);

  if (decrypted.toString("hex") === data.toString("hex")) {
    alert("call wasm encrypt decrypt ok");
  } else {
    alert("call wasm encrypt decrypt failed");
  }


}

function checkError() {
  const pk = Uint8Array.from([0]);
  try {
    ecies.encrypt(pk, data);
  } catch (e) {
    alert(e);
  }
}

document.querySelector("#app").innerHTML = `
  <h1>WASM Test</h1>
  <button id="ok">Check ok</button>
  <button id="error">Check error</button>
`;

document.getElementById("ok").addEventListener("click", () => {
  checkOk();
});
document.getElementById("error").addEventListener("click", () => {
  checkError();
});

window.addEventListener("error", (event) => {
  // catch all other errors
  console.error(event);
});
