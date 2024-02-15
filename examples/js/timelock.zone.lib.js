var SchemesMap = new Map();
SchemesMap.set("secp256k1", 2);
SchemesMap.set("babyjubjub", 1);
SchemesMap.set("bjj", 1);

const timelock_zone_timezone = "Europe/Rome"; // this and the following line refers to the timezone in which the timelock.zone ciphertexts are associated with
const timelock_zone_utc = " UTC+01:00";
const DRAND_GENESIS_TIME = parseInt(1692803367);
const DRAND_FREQUENCY = 3;

async function getPublicKeyfromUrl(Round, Scheme) {
    try {
        return await fetch("https://api.timelock.zone/tlcs/timelock/v1beta1/keypairs/round_and_scheme/" + Round + "/" + SchemesMap.get(Scheme)).then(t => t.text()).then(function(JsonObj) {
            return JSON.parse(JsonObj).keypairs[0].public_key;

        });

    } catch (e) {
        throw ("IOException");
    }
}

async function getSecretKeyfromUrl(Round, Scheme) {
    try {
        return await fetch("https://api.timelock.zone/tlcs/timelock/v1beta1/keypairs/round_and_scheme/" + Round + "/" + SchemesMap.get(Scheme)).then(t => t.text()).then(function(JsonObj) {
            return JSON.parse(JsonObj).keypairs[0].private_key;

        });

    } catch (e) {
        throw ("IOException");
    }
}


function DayToRound(date) { // convert a Date in the first round of the day. For instance, 01/01/2023, 02:34:01 will be converted in the round corresponding to 01/01/2023, 00:00:00
    // date is assumed to be in the timezone=timelock_zone_timezone

    var newdate = date;
    newdate.setHours(0);
    newdate.setMinutes(0);
    newdate.setSeconds(0);
    const t = ((newdate.getTime()) / 1000);
    return (t - DRAND_GENESIS_TIME) / DRAND_FREQUENCY;
}

function DateToRound(date) { // convert a Date in the first round of the hour. For instance, 01/01/2023, 02:34:01 will be converted in the round corresponding to 01/01/2023, 02:00:00
    // date is assumed to be in the timezone=timelock_zone_timezone

    var newdate = date;
    newdate.setMinutes(0);
    newdate.setSeconds(0);
    const t = ((newdate.getTime()) / 1000);
    return (t - DRAND_GENESIS_TIME) / DRAND_FREQUENCY;
}

function UnixTimeToRound(ut) { // convert a Unix time (time in milliseconds since the Unix Epoch)
    const t = ut / 1000;
    return (t - DRAND_GENESIS_TIME) / DRAND_FREQUENCY;
}


function getPublicKeyFromRound(Round, Scheme) {
    try {
        return getPublicKeyfromURL(Round, Scheme);

    } catch (e) {
        throw new("IOException");
    }
}

function getSecretKeyFromRound(Round, Scheme) {
    try {
        return getSecretKeyfromURL(Round, Scheme);

    } catch (e) {
        throw new("IOException");
    }

}
