
let windowObjectReference = null;
let previousUrl = null;

const tenant = 'nicolascosta52468live.onmicrosoft.com';
const authorizationUrl = `https://login.microsoftonline.com/${tenant}/oauth2/v2.0/authorize`;
const accessTokenUrl = `https://login.microsoftonline.com/${tenant}/oauth2/v2.0/token`;
const userInfoUrl = `https://graph.microsoft.com/v1.0/me`;
const clientId = 'fb46042b-6b20-452a-bb76-ecc901d6fd5f';
// const redirectUri = 'https://127.0.0.1:5502/auth/callback.html';
const redirectUri = 'https://auth.diverealities.com/entra_id/';

var codeVerifier = '';
var codeChallenge = '';


function RegisterOpenWindowCallback(){
    window.addEventListener('message', (event) => {
        console.log('Popup URL:', event.data);
        GetOauthToken(event.data);
    });

    console.log('BANANA');
}

async function PrepareOauth (){
    codeVerifier = generateCodeVerifier();
    codeChallenge = await generateCodeChallenge(codeVerifier);
    // window.addEventListener('beforeunload', (event) => {
    //     SendMessageToApp();
    // });
}

function Signin(){
    console.log('StartSignin');
    const redirectEncoded = encodeURIComponent(redirectUri);
    console.log('redirectEncoded:', redirectEncoded);
    // const authUrl = `${authorizationUrl}?client_id=${clientId}&response_type=code&redirect_uri=${redirectEncoded}&scope=openid profile`;
    const authUrl = `${authorizationUrl}?client_id=${clientId}&response_type=code&redirect_uri=${redirectEncoded}&code_challenge=${codeChallenge}&code_challenge_method=S256&scope=openid profile`;

    console.log('authUrl:', authUrl);
    // window.location.href = authUrl;
    OpenSigninWindow(authUrl);
}
function encodeURIComponent(str) {
    return str.replace(/%20/g, '+').replace(/#/g, '%23').replace(/&/g, '%26').replace(/=/g, '%3D').replace(/\?/g, '%3F');
}


function OpenSigninWindow (url){

    const strWindowFeatures = 'toolbar=no, menubar=no, width=600, height=700, top=100, left=100';
        
        url = (url);
        console.log('js:StartSignin', url);
        if (windowObjectReference == null || 
        windowObjectReference != null && windowObjectReference.closed) {
            windowObjectReference = window.open(url, `name`, strWindowFeatures);
            RegisterOpenWindowCallback();
        } else if (this.previousUrl !== url) {
            windowObjectReference = window.open(url, `name`, strWindowFeatures);
            RegisterOpenWindowCallback();
            windowObjectReference.focus();
        } else {
            windowObjectReference.focus();
        }

        previousUrl = url;
}

function generateCodeVerifier() {
    const length = 64;
    const chars = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-._~';
    const array = new Uint8Array(length);
    crypto.getRandomValues(array);

    let result = '';
    for (let i = 0; i < length; i++) {
        result += chars.charAt(array[i] % chars.length);
    }
    return result;
}

function generateCodeChallenge(codeVerifier) {
    const encoder = new TextEncoder();
    const data = encoder.encode(codeVerifier);
    return crypto.subtle.digest('SHA-256', data).then(hashBuffer => {
        const hashArray = Array.from(new Uint8Array(hashBuffer));
        const base64 = btoa(String.fromCharCode.apply(null, hashArray));
        return base64
            .replace(/\+/g, '-')
            .replace(/\//g, '_')
            .replace(/=+$/, '');
    });
}

function GetOauthToken(redirectedUrl){
    const urlencoded = new URL(redirectedUrl);

    const code = urlencoded.searchParams.get('code');
    const error = urlencoded.searchParams.get('error');

    if(error!==null)
        throw new Error('Error in Oauth: ' + error);
    console.log('code:', code);


    const body = new URLSearchParams({
        client_id: clientId,
        redirect_uri: redirectUri,
        grant_type: 'authorization_code',
        code: code,
        code_verifier: codeVerifier,
    });

    fetch(accessTokenUrl, {
        method: 'POST',
        headers: {
            'Content-Type': 'application/x-www-form-urlencoded'
        },
        body: body.toString()
    })
    .then(response => response.json().then(data => {
        if (!response.ok) {
            console.error('Error response:', data);
            throw new Error('HTTP ' + response.status);
        }
        console.log('Access Token:', data);
        GetUserInfo(data.access_token);
    }))
    .catch(error => {
        console.error('Error getting access token:', error);
    });
}

PrepareOauth();

console.log('codeVerifier:', codeVerifier);
console.log('codeChallenge:', codeChallenge);
