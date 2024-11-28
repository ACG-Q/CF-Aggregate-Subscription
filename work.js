let lIl = 'auto'; 




let IlI = '';


let Iil = '';


let lII = 0;


let IlIl = 'CF-Workers-SUB';
let lIil = 6; 


let llIl = 99;
let IlII = 4102329600000;


let IIll = ""

let lIli = []; 
let IlIIi = "SUBAPI.fxxk.dedyn.io"; 
let IilI = "https:
let llI = 'https'; 

function log(obj){
  return new Response(JSON.stringify(obj), {
    status: 200,
  })
}

async function generateToken(payload, secret) {
  const encoder = new TextEncoder();
  const key = await crypto.subtle.importKey(
    "raw",
    encoder.encode(secret),
    { name: "HMAC", hash: { name: "SHA-256" } },
    false,
    ["sign"]
  );

  const data = encoder.encode(payload);
  const signature = await crypto.subtle.sign("HMAC", key, data);

  
  const base64Signature = btoa(String.fromCharCode(...new Uint8Array(signature)));

  return `${payload}.${base64Signature}`;
}


async function verifyToken(token, secret) {
  const [payload, signature] = token.split(".");
  if (!payload || !signature) return false;

  const encoder = new TextEncoder();
  const key = await crypto.subtle.importKey(
    "raw",
    encoder.encode(secret),
    { name: "HMAC", hash: { name: "SHA-256" } },
    false,
    ["verify"]
  );

  
  const decodedSignature = Uint8Array.from(atob(signature), (c) => c.charCodeAt(0));

  const valid = await crypto.subtle.verify(
    "HMAC",
    key,
    decodedSignature,
    encoder.encode(payload)
  );

  return valid ? payload : null;
}

function parseCookies(cookieHeader) {
  const cookies = {};
  if (!cookieHeader) return cookies;
  
  cookieHeader.split(";").forEach((cookie) => {
    const [key, value] = cookie.split("=").map((v) => v.trim());
    cookies[key] = value;
  });

  return cookies;
}


async function isAuthenticated(request, env) {
  const cookies = parseCookies(request.headers.get("Cookie"));
  const token = cookies.auth;

  if (!token) return false;

  
  const payload = await verifyToken(token, env.SECRET);
  if (!payload) return false;

  
  const timestamp = parseInt(payload, 10);
  const now = Date.now();
  const maxAge = 3600 * 1000; 

  if (now - timestamp > maxAge) return false;

  return true;
}


export default {
  async fetch(request, env) {
    
    const userAgentHeader = request.headers.get('User-Agent');
    const userAgent = userAgentHeader ? userAgentHeader.toLowerCase() : "null";

    
    const url = new URL(request.url);
    const token = url.searchParams.get('token');

    
    const kv = env.CONFIG_KV
    
    let _variables = await kv.get("variables")
    const variables = _variables ? JSON.parse(_variables) : {}

    
    lIl = variables.lIl || lIl;
    IlI = variables.IlI || IlI;
    Iil = variables.Iil || Iil;
    lII = variables.lII || lII;
    IlIIi = variables.IlIIi || IlIIi;
    IilI = variables.IilI || IilI;
    IlIl = variables.IlIl || IlIl;
    IIll = variables.IIll || IIll;

    
    if (variables.lIli) lIli = await parseLinks(variables.lIli);

    if (IlIIi.includes("http:
      IlIIi = IlIIi.split("
      llI = 'http';
    } else {
      IlIIi = IlIIi.split("
    }

    
    let todayTimestamp = Math.ceil(new Date().setHours(0, 0, 0, 0) / 1000);

    
    const generatedToken = await doubleMD5Hash(`${lIl}${todayTimestamp}`);

    
    llIl = llIl * 1099511627776;
    let availableTraffic = Math.floor(((IlII - Date.now()) / IlII) * llIl / 2); 
    let expireTimeInSeconds = Math.floor(IlII / 1000); 

    lIil = variables.lIil || lIil;

    let combinedLinks = await parseLinks(IIll + '\n' + lIli.join('\n'));
    let selfNodes = "";
    let subscriptionLinksStr = "";
    for (let x of combinedLinks) {
      if (x.toLowerCase().startsWith('http')) {
        subscriptionLinksStr += x + '\n';
      } else {
        selfNodes += x + '\n';
      }
    }
    IIll = selfNodes;
    lIli = await parseLinks(subscriptionLinksStr);

    if (!(token == lIl || token == generatedToken || url.pathname == ("/" + lIl) || url.pathname.includes("/" + lIl + "?"))) {

      
      if (url.pathname === "/login" && request.method === "POST") {
        return await handleLogin(request, env);
      }

      
      if (url.pathname === "/manage") {
        const authenticated = await isAuthenticated(request, env);
        if (!authenticated) {
          return await renderLoginPage();
        }

        return await renderManagePage(env); 
      }

      
      if (url.pathname === "/api/variables") {
        const authenticated = await isAuthenticated(request, env);
        if (!authenticated) {
          return await renderNginxPage()
        }
        return await handleVariablesAPI(request, env);
      }

      if (lII == 1 && url.pathname !== "/" && url.pathname !== "/favicon.ico") {
        await sendTelegramNotification(`#异常访问 ${IlIl}`, request.headers.get('CF-Connecting-IP'), `UA: ${userAgent}</tg-spoiler>\n域名: ${url.hostname}\n<tg-spoiler>入口: ${url.pathname + url.search}</tg-spoiler>`);
      }

      if (variables.URL302) {
        return Response.redirect(variables.URL302, 302);
      } else if (variables.URL) {
        return await proxyURL(variables.URL, url);
      } else {
        return await renderNginxPage()
      }

    } else {
      
      await sendTelegramNotification(`#获取订阅 ${IlIl}`, request.headers.get('CF-Connecting-IP'), `UA: ${userAgentHeader}</tg-spoiler>\n域名: ${url.hostname}\n<tg-spoiler>入口: ${url.pathname + url.search}</tg-spoiler>`);

      let subscriptionFormat = 'base64';
      if (userAgent.includes('null') || userAgent.includes('subconverter') || userAgent.includes('nekobox') || userAgent.includes(('CF-Workers-SUB').toLowerCase())) {
        subscriptionFormat = 'base64';
      } else if (userAgent.includes('clash') || (url.searchParams.has('clash') && !userAgent.includes('subconverter'))) {
        subscriptionFormat = 'clash';
      } else if (userAgent.includes('sing-box') || userAgent.includes('singbox') || ((url.searchParams.has('sb') || url.searchParams.has('singbox')) && !userAgent.includes('subconverter'))) {
        subscriptionFormat = 'singbox';
      } else if (userAgent.includes('surge') || (url.searchParams.has('surge') && !userAgent.includes('subconverter'))) {
        subscriptionFormat = 'surge';
      } else if (userAgent.includes('quantumult%20x') || (url.searchParams.has('quanx') && !userAgent.includes('subconverter'))) {
        subscriptionFormat = 'quanx';
      } else if (userAgent.includes('loon') || (url.searchParams.has('loon') && !userAgent.includes('subconverter'))) {
        subscriptionFormat = 'loon';
      }

      let subconverterUrl;
      let subscriptionConversionURL = `${url.origin}/${await doubleMD5Hash(generatedToken)}?token=${generatedToken}`;

      
      let requestData = IIll;
      let appendUA = 'v2rayn';
      if (url.searchParams.has('clash')) appendUA = 'clash';
      else if (url.searchParams.has('singbox')) appendUA = 'singbox';
      else if (url.searchParams.has('surge')) appendUA = 'surge';
      else if (url.searchParams.has('quanx')) appendUA = 'Quantumult%20X';
      else if (url.searchParams.has('loon')) appendUA = 'Loon';

      const subscriptionResponse = await getSubscriptionData(lIli, request, appendUA, userAgentHeader);
      requestData += subscriptionResponse[0].join('\n');
      subscriptionConversionURL += "|" + subscriptionResponse[1];

      if (variables.WARP) {
        subscriptionConversionURL += "|" + (await parseLinks(variables.WARP)).join("|");
      }


      
      const utf8Encoder = new TextEncoder();
      const encodedData = utf8Encoder.encode(requestData);
      const utf8Decoder = new TextDecoder();
      const text = utf8Decoder.decode(encodedData);

      
      const uniqueLines = new Set(text.split('\n'));
      const result = [...uniqueLines].join('\n');

      let base64Data;
      try {
        base64Data = btoa(result);
      } catch (e) {
        base64Data = encodeBase64(result);
      }

      
      if (subscriptionFormat == 'base64' || token == generatedToken) {
        return new Response(base64Data, {
          headers: {
            "content-type": "text/plain; charset=utf-8",
            "Profile-Update-Interval": `${lIil}`,
            "Subscription-Userinfo": `upload=${availableTraffic}; download=${availableTraffic}; llIl=${llIl}; expireTimeInSeconds=${expireTimeInSeconds}`,
          }
        });
      } else {
        
        let conversionURL;
        switch (subscriptionFormat) {
          case 'clash':
            conversionURL = `${llI}:
            break;
          case 'singbox':
            conversionURL = `${llI}:
            break;
          case 'surge':
            conversionURL = `${llI}:
            break;
          case 'quanx':
            conversionURL = `${llI}:
            break;
          case 'loon':
            conversionURL = `${llI}:
            break;
          default:
            conversionURL = subscriptionConversionURL;
        }
      }


      try {
        const subconverterResponse = await fetch(subconverterUrl);

        if (!subconverterResponse.ok) {
          return new Response(base64Data, {
            headers: {
              "content-type": "text/plain; charset=utf-8",
              "Profile-Update-Interval": `${lIil}`,
              "Subscription-Userinfo": `upload=${availableTraffic}; download=${availableTraffic}; llIl=${llIl}; expireTimeInSeconds=${expireTimeInSeconds}`,
            }
          });
          
        }
        let subconverterContent = await subconverterResponse.text();
        if (subscriptionFormat == 'clash') subconverterContent = await fixClashConfig(subconverterContent);
        return new Response(subconverterContent, {
          headers: {
            "Content-Disposition": `attachment; filename*=utf-8''${encodeURIComponent(IlIl)}; filename=${IlIl}`,
            "content-type": "text/plain; charset=utf-8",
            "Profile-Update-Interval": `${lIil}`,
            "Subscription-Userinfo": `upload=${availableTraffic}; download=${availableTraffic}; llIl=${llIl}; expireTimeInSeconds=${expireTimeInSeconds}`,

          },
        });
      } catch (error) {
        return new Response(base64Data, {
          headers: {
            "content-type": "text/plain; charset=utf-8",
            "Profile-Update-Interval": `${lIil}`,
            "Subscription-Userinfo": `upload=${availableTraffic}; download=${availableTraffic}; llIl=${llIl}; expireTimeInSeconds=${expireTimeInSeconds}`,
          }
        });
      }
    }
  }
};


async function parseLinks(lIli) {
  
  let cleanedText = lIli.replace(/[	"'|\r\n]+/g, ',').replace(/,+/g, ',');

  
  if (cleanedText.charAt(0) === ',') cleanedText = cleanedText.slice(1);
  if (cleanedText.charAt(cleanedText.length - 1) === ',') cleanedText = cleanedText.slice(0, cleanedText.length - 1);

  
  const resultArray = cleanedText.split(',');

  return resultArray;
}





async function sendTelegramNotification(type, ip, add_data = "") {
  
  if (IlI !== '' && Iil !== '') {
    let msg = "";

    
    const response = await fetch(`http:

    if (response.status === 200) {
      const ipInfo = await response.json();
      
      msg = `${type}\nIP: ${ip}\n国家: ${ipInfo.country}\n<tg-spoiler>城市: ${ipInfo.city}\n组织: ${ipInfo.org}\nASN: ${ipInfo.as}\n${add_data}`;
    } else {
      
      msg = `${type}\nIP: ${ip}\n<tg-spoiler>${add_data}`;
    }

    
    let url = `https:

    
    return fetch(url, {
      method: 'get',
      headers: {
        'Accept': 'text/html,application/xhtml+xml,application/xml;',
        'Accept-Encoding': 'gzip, deflate, br',
        'User-Agent': 'Mozilla/5.0 Chrome/90.0.4430.72'
      }
    });
  }
}


function base64Decode(str) {
  const bytes = new Uint8Array(atob(str).split('').map(c => c.charCodeAt(0)));
  const decoder = new TextDecoder('utf-8');
  return decoder.decode(bytes);
}


async function doubleMD5Hash(text) {
  
  const encoder = new TextEncoder();

  
  const firstHash = await crypto.subtle.digest('MD5', encoder.encode(text));
  const firstHashArray = Array.from(new Uint8Array(firstHash));
  const firstHex = firstHashArray.map(byte => byte.toString(16).padStart(2, '0')).join('');

  
  const secondHashInput = firstHex.slice(7, 27);
  const secondHash = await crypto.subtle.digest('MD5', encoder.encode(secondHashInput));
  const secondHashArray = Array.from(new Uint8Array(secondHash));
  const secondHex = secondHashArray.map(byte => byte.toString(16).padStart(2, '0')).join('');

  
  return secondHex.toLowerCase();
}


function fixClashConfig(configContent) {
  
  if (configContent.includes('wireguard') && !configContent.includes('remote-dns-resolve')) {
    let configLines;

    
    if (configContent.includes('\r\n')) {
      configLines = configContent.split('\r\n');
    } else {
      configLines = configContent.split('\n');
    }

    let updatedConfig = "";

    
    for (let line of configLines) {
      
      if (line.includes('type: wireguard')) {
        const legacyConfigPart = `, mtu: 1280, udp: true`; 
        const correctedConfigPart = `, mtu: 1280, remote-dns-resolve: true, udp: true`; 

        
        updatedConfig += line.replace(new RegExp(legacyConfigPart, 'g'), correctedConfigPart) + '\n';
      } else {
        updatedConfig += line + '\n'; 
      }
    }

    
    configContent = updatedConfig;
  }

  return configContent; 
}


async function proxyURL(proxyURL, url) {
  const URLs = await parseLinks(proxyURL);
  const fullURL = URLs[Math.floor(Math.random() * URLs.length)];

  
  let parsedURL = new URL(fullURL);
  console.log(parsedURL);
  
  let URLProtocol = parsedURL.protocol.slice(0, -1) || 'https';
  let URLHostname = parsedURL.hostname;
  let URLPathname = parsedURL.pathname;
  let URLSearch = parsedURL.search;

  
  if (URLPathname.charAt(URLPathname.length - 1) == '/') {
    URLPathname = URLPathname.slice(0, -1);
  }
  URLPathname += url.pathname;

  
  let newURL = `${URLProtocol}:

  
  let response = await fetch(newURL);

  
  let newResponse = new Response(response.body, {
    status: response.status,
    statusText: response.statusText,
    headers: response.headers
  });

  
  
  
  newResponse.headers.set('X-New-URL', newURL);

  return newResponse;
}


async function getSubscriptionData(apiUrls, request, appendUA, userAgentHeader) {
  if (!apiUrls || apiUrls.length === 0) {
    return [];  
  }

  let validApiResponses = "";  
  let convertedUrls = "";  
  let errorUrls = "";  

  const abortController = new AbortController();  
  const timeoutId = setTimeout(() => {
    abortController.abort();  
  }, 2000);

  try {
    
    const maxConcurrentRequests = 5; 
    const responses = [];

    
    for (let i = 0; i < apiUrls.length; i += maxConcurrentRequests) {
      const currentBatch = apiUrls.slice(i, i + maxConcurrentRequests);
      const batchResults = await Promise.allSettled(currentBatch.map(apiUrl =>
        getUrl(request, apiUrl, appendUA, userAgentHeader)
          .then(response => response.ok ? response.text() : Promise.reject(response))
      ));

      responses.push(...batchResults);  
    }

    
    const processedResponses = responses.map((response, index) => {
      if (response.status === 'rejected') {
        const reason = response.reason;
        if (reason && reason.name === 'AbortError') {
          return { status: '超时', content: null, apiUrl: apiUrls[index] };  
        }
        console.error(`请求失败: ${apiUrls[index]}, 错误信息: ${reason.status} ${reason.statusText}`);
        return { status: '请求失败', content: null, apiUrl: apiUrls[index] };  
      }
      return { status: response.status, content: response.value, apiUrl: apiUrls[index] };  
    });

    
    for (const response of processedResponses) {
      if (response.status === 'fulfilled') {
        const content = await response.content || 'null';  

        if (content.includes('proxies') && content.includes('proxy-groups')) {
          convertedUrls += "|" + response.apiUrl;  
        } else if (content.includes('outbounds') && content.includes('inbounds')) {
          convertedUrls += "|" + response.apiUrl;  
        } else if (content.includes(':
          validApiResponses += content + '\n';  
        } else if (isValidBase64(content)) {
          validApiResponses += base64Decode(content) + '\n';  
        } else {
          const errorLink = `trojan:
          console.log(errorLink);
          errorUrls += `${errorLink}\n`;  
        }
      }
    }
  } catch (error) {
    console.error(`请求异常: ${error.message}`);  
  } finally {
    clearTimeout(timeoutId);  
  }

  
  const subscriptionContent = await parseLinks(validApiResponses + errorUrls);
  return [subscriptionContent, convertedUrls];
}


async function getUrl(request, targetUrl, appendUA, userAgentHeader) {
  
  const newHeaders = new Headers(request.headers);
  newHeaders.set("User-Agent", `v2rayN/${appendUA} cmliu/CF-Workers-SUB ${userAgentHeader}`);

  
  const modifiedRequest = new Request(targetUrl, {
    method: request.method,
    headers: newHeaders,
    body: request.method === "GET" ? null : request.body,
    redirect: "follow"
  });

  
  console.log(`请求URL: ${targetUrl}`);
  console.log(`请求头: ${JSON.stringify([...newHeaders])}`);
  console.log(`请求方法: ${request.method}`);
  console.log(`请求体: ${request.method === "GET" ? null : request.body}`);

  
  return fetch(modifiedRequest);
}

function isValidBase64(str) {
  const base64Regex = /^[A-Za-z0-9+/=]+$/;
  return base64Regex.test(str);
}

function encodeBase64(data) {
  const binary = new TextEncoder().encode(data);
  let base64 = '';
  const chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/';

  for (let i = 0; i < binary.length; i += 3) {
    const byte1 = binary[i];
    const byte2 = binary[i + 1] || 0;
    const byte3 = binary[i + 2] || 0;

    base64 += chars[byte1 >> 2];
    base64 += chars[((byte1 & 3) << 4) | (byte2 >> 4)];
    base64 += chars[((byte2 & 15) << 2) | (byte3 >> 6)];
    base64 += chars[byte3 & 63];
  }

  const padding = 3 - (binary.length % 3 || 3);
  return base64.slice(0, base64.length - padding) + '=='.slice(0, padding);
}



async function renderManagePage(env) {
  return new Response(`<!DOCTYPE html><html lang=zh-CN><head><meta charset=UTF-8><meta name=viewport content="width=device-width,initial-scale=1"><link rel=icon type=image/png href=/assets/favicon-96x96.png sizes=96x96><link rel=icon type=image/svg+xml href=/assets/favicon.svg><link rel="shortcut icon" href=/assets/favicon.ico><link rel=apple-touch-icon sizes=180x180 href=/assets/apple-touch-icon.png><link rel=manifest href=/assets/site.webmanifest><title>聚合订阅器-配置项管理</title><style>body{font-family:Arial,sans-serif;margin:0;padding:20px;background-color:#f8f9fa}.container{max-width:900px;margin:auto;background:#fff;padding:40px;border-radius:8px;box-shadow:0 4px 10px rgba(0,0,0,.1)}h1{text-align:center;color:#343a40;margin-bottom:30px}h2{margin-top:40px;color:#007bff;border-bottom:2px solid #007bff;padding-bottom:8px;font-size:20px}.form-group{margin-bottom:25px;display:flex;flex-direction:column}label{font-size:16px;font-weight:700;margin-bottom:8px;color:#495057}input,select,textarea{width:100%;padding:12px;margin-top:8px;font-size:16px;border:1px solid #ced4da;border-radius:8px;background-color:#f8f9fa}textarea{resize:vertical;min-height:100px}button{padding:12px 20px;background-color:#007bff;color:#fff;border:none;border-radius:8px;cursor:pointer;font-size:16px;transition:background-color .3s;margin-top:15px}button:hover{background-color:#0056b3}.clear-btn{background-color:#dc3545;color:#fff;border:none;border-radius:6px;cursor:pointer;height:100%;box-sizing:border-box;padding:12px;margin-top:8px;font-size:16px}.clear-btn:hover{background-color:#c82333}.form-group .input-group{display:flex;align-items:center}.form-group .input-group input{flex:1}.form-group .input-group .clear-btn{margin-left:10px}table{width:100%;margin-top:30px;border-collapse:collapse}td,th{padding:12px;text-align:left;border:1px solid #ced4da}th{background-color:#f8f9fa}td pre{white-space:pre-wrap;word-wrap:break-word}.description{font-size:14px;color:#6c757d;margin-top:8px}.category-title{font-size:18px;color:#007bff;border-bottom:2px solid #007bff;padding-bottom:5px;margin-bottom:15px}.button-container{position:fixed;right:20px;bottom:20px;display:flex;flex-direction:column;gap:10px}.button-container button{padding:10px 15px;background-color:#007bff;color:#fff;border:none;border-radius:8px;cursor:pointer;font-size:14px;box-shadow:0 2px 4px rgba(0,0,0,.2);transition:background-color .3s}.button-container button:hover{background-color:#0056b3}.button-container .scroll-top-btn{background-color:#6c757d}.button-container .scroll-top-btn:hover{background-color:#343a40}</style></head><body><div class=container><h1>配置项管理</h1><div class=category-title>用户授权设置</div><div class=form-group><label for=lIl>用户访问的授权令牌 (lIl):</label><div class=input-group><input type=text id=lIl> <button class=clear-btn onclick='clearValue("lIl")'>清空</button></div><div class=description>通过 UUID 或自定义字符串生成，作为用户的访问令牌。</div></div><div class=form-group><label for=IlI>Telegram Bot Token (IlI):</label><div class=input-group><input type=text id=IlI> <button class=clear-btn onclick='clearValue("IlI")'>清空</button></div><div class=description>用于推送通知的 Telegram 机器人 Token，可以为空。</div></div><div class=form-group><label for=Iil>Telegram Chat ID (Iil):</label><div class=input-group><input type=text id=Iil> <button class=clear-btn onclick='clearValue("Iil")'>清空</button></div><div class=description>指定接收通知的 Telegram 会话 ID，可以为空。</div></div><div class=form-group><label for=lII>启用 Telegram 推送 (lII):</label> <select id=lII><option value=1>推送所有访问信息</option><option value=0>仅推送异常访问</option></select><div class=description>选择是否启用 Telegram 推送通知。</div></div><div class=category-title>订阅设置</div><div class=form-group><label for=IlIl>自定义订阅文件名 (IlIl):</label><div class=input-group><input type=text id=IlIl> <button class=clear-btn onclick='clearValue("IlIl")'>清空</button></div><div class=description>设置自定义的订阅文件名。</div></div><div class=form-group><label for=lIil>自定义订阅更新时间 (lIil):</label><div class=input-group><input type=number id=lIil> <button class=clear-btn onclick='clearValue("lIil")'>清空</button></div><div class=description>设置自定义的订阅更新时间，单位为小时。</div></div><div class=category-title>流量与到期设置</div><div class=form-group><label for=llIl>节点流量 (llIl):</label><div class=input-group><input type=text id=llIl> <button class=clear-btn onclick='clearValue("llIl")'>清空</button></div><div class=description>设置节点流量，单位为 TB。</div></div><div class=form-group><label for=IlII>节点到期时间 (IlII):</label><div class=input-group><input type=number id=IlII> <button class=clear-btn onclick='clearValue("IlII")'>清空</button></div><div class=description>设置节点到期时间，时间戳格式。</div></div><div class=category-title>配置链接设置</div><div class=form-group><label for=IIll>订阅聚合信息:</label><div class=input-group><textarea id=IIll></textarea> <button class=clear-btn onclick='clearValue("IIll")'>清空</button></div><div class=description>包含节点链接和自定义订阅数据。ps. 通过换行来分割</div></div><div class=form-group><label for=lIli>订阅链接 (lIli):</label><div class=input-group><input type=text id=lIli> <button class=clear-btn onclick='clearValue("lIli")'>清空</button></div><div class=description>存储用户的节点和订阅链接。</div></div><div class=form-group><label for=IlIIi>订阅转换后端 API (IlIIi):</label><div class=input-group><input type=text id=IlIIi> <button class=clear-btn onclick='clearValue("IlIIi")'>清空</button></div><div class=description>在线订阅转换后端的 API 地址。</div></div><div class=form-group><label for=IilI>订阅配置文件 URL (IilI):</label><div class=input-group><input type=text id=IilI> <button class=clear-btn onclick='clearValue("IilI")'>清空</button></div><div class=description>订阅配置文件的 URL。</div></div><div class=form-group><label for=llI>订阅转换服务协议 (llI):</label><div class=input-group><input type=text id=llI> <button class=clear-btn onclick='clearValue("llI")'>清空</button></div><div class=description>支持 http 或 https。</div></div><div class=category-title>WARP 与 URL 设置</div><div class=form-group><label for=warp>是否使用 WARP 服务 (WARP):</label><div class=input-group><input type=text id=warp> <button class=clear-btn onclick='clearValue("warp")'>清空</button></div><div class=description>是否使用 WARP 服务，具体用途不明确。</div></div><div class=form-group><label for=url302>302 重定向 URL (URL302):</label><div class=input-group><input type=text id=url302> <button class=clear-btn onclick='clearValue("url302")'>清空</button></div><div class=description>302 重定向的 URL。</div></div><div class=form-group><label for=url>备用 URL (URL):</label><div class=input-group><input type=text id=url> <button class=clear-btn onclick='clearValue("url")'>清空</button></div><div class=description>备用 URL。</div></div></div><div class=button-container><button id=saveBtn>保存配置</button> <button id=scrollTopBtn class=scroll-top-btn>回到顶部</button></div><script>function clearValue(id) {
        document.getElementById(id).value = '';
    }

    async function fetchVariables() {
      try {
          const response = await fetch('api/variables');
          const data = await response.json();
          const variables = JSON.parse(data.variables || "{}");

          
          const defaultValues = {
              lIl: 'auto',
              IlI: '',
              Iil: '',
              lII: '0',
              IlIl: 'CF-Workers-SUB',
              lIil: 6,
              llIl: 99,
              IlII: 4102329600000,
              IIll: [],
              lIli: [],
              IlIIi: 'SUBAPI.fxxk.dedyn.io',
              IilI: 'https:
              llI: 'https',
          };

		  let newData = Object.assign({}, defaultValues, variables);
  
          
          document.getElementById('lIl').value = newData.lIl;
          document.getElementById('IlI').value = newData.IlI;
          document.getElementById('Iil').value = newData.Iil;
          document.getElementById('lII').value = newData.lII;
          document.getElementById('IlIl').value = newData.IlIl;
          document.getElementById('lIil').value = newData.lIil;
          document.getElementById('llIl').value = newData.llIl;
          document.getElementById('IlII').value = newData.IlII;
          document.getElementById('IIll').value = newData.IIll.join("\\n");
          document.getElementById('lIli').value = newData.lIli;
          document.getElementById('IlIIi').value = newData.IlIIi;
          document.getElementById('IilI').value = newData.IilI;
          document.getElementById('llI').value = newData.llI;
      } catch (error) {
          console.error('获取变量失败：', error);
          alert('无法加载配置，请检查网络连接或稍后重试。');
      }
    }

    
    document.getElementById('scrollTopBtn').onclick = () => {
        window.scrollTo({ top: 0, behavior: 'smooth' });
    };
  

    
    document.getElementById('saveBtn').onclick = async () => {
        const variables = Object.fromEntries(
          Object.entries({
            lIl: document.getElementById('lIl').value,
            IlI: document.getElementById('IlI').value,
            Iil: document.getElementById('Iil').value,
            lII: document.getElementById('lII').value,
            IlIl: document.getElementById('IlIl').value,
            lIil: document.getElementById('lIil').value,
            llIl: document.getElementById('llIl').value,
            IlII: document.getElementById('IlII').value,
            IIll: document.getElementById('IIll').value.split("\\n"),
            lIli: document.getElementById('lIli').value,
            IlIIi: document.getElementById('IlIIi').value,
            IilI: document.getElementById('IilI').value,
            llI: document.getElementById('llI').value,
            WARP: document.getElementById('warp').value,
            URL302: document.getElementById('url302').value,
            URL: document.getElementById('url').value,
          })
          .filter(([key, value]) => value !== '' && value != null)
        );

        const response = await fetch('api/variables', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
            },
            body: JSON.stringify({variables}),
        });

        if (response.ok) {
            alert("配置已保存！");
        } else {
            alert("保存失败，请稍后重试！");
        }
    };

    
    window.onload = fetchVariables;</script></body></html>`, { headers: { "Content-Type": "text/html; charset=UTF-8" } });
}

async function renderLoginPage() {
  return new Response(`<!DOCTYPE html><html lang=zh-CN><head><meta charset=UTF-8><meta name=viewport content="width=device-width,initial-scale=1"><link rel=icon type=image/png href=/assets/favicon-96x96.png sizes=96x96><link rel=icon type=image/svg+xml href=/assets/favicon.svg><link rel="shortcut icon" href=/assets/favicon.ico><link rel=apple-touch-icon sizes=180x180 href=/assets/apple-touch-icon.png><link rel=manifest href=/assets/site.webmanifest><title>登录</title><style>body{font-family:Arial,sans-serif;margin:0;padding:0;display:flex;justify-content:center;align-items:center;height:100vh;background:linear-gradient(135deg,#74ebd5,#acb6e5);overflow:hidden}.login-container{background:#fff;padding:30px;border-radius:10px;box-shadow:0 4px 20px rgba(0,0,0,.2);text-align:center;width:350px;animation:fadeIn 1s ease-in-out}.login-container h1{margin-bottom:20px;color:#333;font-size:24px}.login-container input{width:100%;padding:12px;margin-bottom:15px;border:1px solid #ccc;border-radius:5px;font-size:16px;transition:border-color .3s ease;box-sizing:border-box}.login-container input:focus{border-color:#007bff;outline:0}.login-container button{width:100%;padding:12px;background-color:#007bff;color:#fff;border:none;border-radius:5px;font-size:16px;cursor:pointer;transition:background-color .3s ease}.login-container button:hover{background-color:#0056b3}.login-container .error{color:red;margin-top:10px;font-size:14px;display:none}@keyframes fadeIn{from{opacity:0;transform:scale(.9)}to{opacity:1;transform:scale(1)}}</style></head><body><div class=login-container><h1>欢迎登录</h1><input type=password id=password placeholder=请输入密码> <button onclick=login()>登录</button><p id=error class=error>密码错误，请重试！</p></div><script>async function login(){var e=document.getElementById("password").value,t=document.getElementById("error");t.style.display="none";try{(await fetch("/login",{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify({password:e})})).ok?window.location.href="/manage":t.style.display="block"}catch(e){t.textContent="登录失败，请稍后再试！",t.style.display="block"}}</script></body></html>`, { headers: { "Content-Type": "text/html; charset=UTF-8" } });
}



async function renderNginxPage() {
  return new Response(`<!DOCTYPE html><html lang=zh-CN><head><meta charset=UTF-8><meta name=viewport content="width=device-width,initial-scale=1"><link rel=icon type=image/png href=/assets/favicon-96x96.png sizes=96x96><link rel=icon type=image/svg+xml href=/assets/favicon.svg><link rel="shortcut icon" href=/assets/favicon.ico><link rel=apple-touch-icon sizes=180x180 href=/assets/apple-touch-icon.png><link rel=manifest href=/assets/site.webmanifest><title>网站维护中</title><style>body{font-family:Arial,sans-serif;margin:0;padding:0;background-color:#f4f4f4;color:#333;display:flex;justify-content:center;align-items:center;height:100vh;position:relative}.container{width:50%;background:#fff;box-shadow:0 4px 6px rgba(0,0,0,.1);border-radius:8px;padding:30px;text-align:center;opacity:0;transform:translateY(50px);transition:opacity 1s,transform 1s}.container.visible{opacity:1;transform:translateY(0)}.container h1{font-size:2rem;margin-bottom:10px;color:#d9534f}.container .message{font-size:1.2rem;color:#555;margin-bottom:20px}footer{margin-top:20px;font-size:.9rem;color:#aaa}.corner{position:absolute;width:50px;height:50px;background-color:transparent;z-index:10;cursor:pointer}.corner-top-left{top:0;left:0}.corner-top-right{top:0;right:0}.corner-bottom-left{bottom:0;left:0}.corner-bottom-right{bottom:0;right:0}</style></head><body><div class=container id=content><h1>网站暂时关闭</h1><div class=message>由于当前网站受到大规模 DDoS 攻击，暂时关闭访问。</div><footer>© <span id=currentYear></span> 网站运营团队</footer></div><div class="corner corner-top-left" id=corner1 onclick=registerClick(1)></div><div class="corner corner-top-right" id=corner2 onclick=registerClick(2)></div><div class="corner corner-bottom-right" id=corner3 onclick=registerClick(3)></div><div class="corner corner-bottom-left" id=corner4 onclick=registerClick(4)></div><script>document.getElementById("currentYear").textContent=(new Date).getFullYear();let clickedCorners=[],expectedOrder=[],firstCorner=null;function registerClick(e){0===expectedOrder.length&&(firstCorner=e,expectedOrder=generateOrder(firstCorner)),e===expectedOrder[clickedCorners.length]?(clickedCorners.push(e),4===clickedCorners.length&&(window.location.href="/manage")):resetClicks()}function resetClicks(){clickedCorners=[],expectedOrder=[],firstCorner=null}function generateOrder(e){var r=[1,2,3,4],t=r.indexOf(e);if(-1===t)return[];var n=(new Date).getDate();let c;return c=n%2==0?[e].concat(r.slice(0,t).reverse()).concat(r.slice(t+1).reverse()):[e].concat(r.slice(t+1)).concat(r.slice(0,t+1))}window.onload=function(){document.getElementById("content").classList.add("visible")}</script></body></html>`, { headers: { "Content-Type": "text/html; charset=UTF-8" } });
}


async function handleLogin(request, env) {
    const { password } = await request.json();

    if (password === env.PWD) {
      const maxAge = 3600; 
      const expires = new Date(Date.now() + maxAge * 1000).toUTCString();
  
      
      const tokenPayload = `${Date.now()}`; 
      const token = await generateToken(tokenPayload, env.SECRET);

      
  
      return new Response("登录成功！", {
        status: 200,
        headers: {
          "Set-Cookie": `auth=${token}; Expires=${expires}; Max-Age=${maxAge}; HttpOnly; Secure; Path=/`,
          "Content-Type": "application/json",
        },
      });
    } else {
      return new Response("密码错误！", { status: 401, headers: { "Content-Type": "text/plain" } });
    }
  }
  



async function handleVariablesAPI(request, env) {
  const method = request.method;
  const kv = env.CONFIG_KV;

  if (method === "GET") {
    
    const keys = await kv.list();
    const data = {};
    for (const key of keys.keys) {
      data[key.name] = await kv.get(key.name);
    }
    return new Response(JSON.stringify(data), { headers: { "Content-Type": "application/json" } });
  } else if (method === "POST") {
    
    const variables = await request.json();
    if (typeof variables !== 'object' || variables === null || Object.keys(variables).length === 0) {
      return new Response("Bad Request: The request body should be an object with key-value pairs.", { status: 400 });
    }
    for (const [key, value] of Object.entries(variables)) {
      if (!key || !value) {
        return new Response("Bad Request: Each key and value must be non-empty.", { status: 400 });
      }
      await kv.put(key, JSON.stringify(value));
    }
    return new Response("OK");
  } else if (method === "DELETE") {
    
    const url = new URL(request.url);
    const key = url.searchParams.get("key");
    if (!key) return new Response("Bad Request", { status: 400 });
    await kv.delete(key);
    return new Response("OK");
  }

  return new Response("Method Not Allowed", { status: 405 });
}