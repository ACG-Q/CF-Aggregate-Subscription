let lIl="auto",IlI="",Iil="",lII=0,IlIl="CF-Workers-SUB",lIil=6,llIl=99,IlII=41023296e5,IIll="",lIli=[],IlIIi="SUBAPI.fxxk.dedyn.io",IilI="https://raw.githubusercontent.com/cmliu/ACL4SSR/main/Clash/config/ACL4SSR_Online_MultiCountry.ini",llI="https";function log(e){return new Response(JSON.stringify(e),{status:200})}async function generateToken(e,t){var l=new TextEncoder,t=await crypto.subtle.importKey("raw",l.encode(t),{name:"HMAC",hash:{name:"SHA-256"}},!1,["sign"]),l=l.encode(e),t=await crypto.subtle.sign("HMAC",t,l);return e+"."+btoa(String.fromCharCode(...new Uint8Array(t)))}async function verifyToken(e,t){var l,[e,n]=e.split(".");return!(!e||!n)&&(l=new TextEncoder,t=await crypto.subtle.importKey("raw",l.encode(t),{name:"HMAC",hash:{name:"SHA-256"}},!1,["verify"]),n=Uint8Array.from(atob(n),e=>e.charCodeAt(0)),await crypto.subtle.verify("HMAC",t,n,l.encode(e))?e:null)}function parseCookies(e){let l={};return e&&e.split(";").forEach(e=>{var[e,t]=e.split("=").map(e=>e.trim());l[e]=t}),l}async function isAuthenticated(e,t){var e=parseCookies(e.headers.get("Cookie")).auth;return!!e&&!(!(e=await verifyToken(e,t.SECRET))||(t=parseInt(e,10),36e5<Date.now()-t))}export default{async fetch(r,a){var e,i=new URL(r.url),s=i.searchParams.get("token"),c=r.headers.get("User-Agent"),d=c?c.toLowerCase():"null",u=await a.CONFIG_KV.get("variables"),u=u?JSON.parse(u):{},p=(lIl=u.lIl||lIl,IlI=u.IlI||IlI,Iil=u.Iil||Iil,lII=u.lII||lII,IlIIi=u.IlIIi||IlIIi,IilI=u.IilI||IilI,IlIl=u.IlIl||IlIl,IIll=u.IIll||IIll,u.lIli&&(lIli=await parseLinks(u.lIli)),IlIIi.includes("http://")?(IlIIi=IlIIi.split("//")[1],llI="http"):IlIIi=IlIIi.split("//")[1]||IlIIi,Math.ceil((new Date).setHours(0,0,0,0)/1e3)),p=await doubleMD5Hash(""+lIl+p),I=(llIl*=1099511627776,Math.floor((IlII-Date.now())/IlII*llIl/2)),g=Math.floor(IlII/1e3),f=(lIil=u.lIil||lIil,await parseLinks(IIll+"\n"+lIli.join("\n")));let t="",l="";for(e of f)e.toLowerCase().startsWith("http")?l+=e+"\n":t+=e+"\n";if(IIll=t,lIli=await parseLinks(l),s!=lIl&&s!=p&&i.pathname!="/"+lIl&&!i.pathname.includes("/"+lIl+"?"))return"/login"===i.pathname&&"POST"===r.method?handleLogin(r,a):"/manage"===i.pathname?await isAuthenticated(r,a)?renderManagePage(a):renderLoginPage():"/api/variables"===i.pathname?await isAuthenticated(r,a)?handleVariablesAPI(r,a):renderNginxPage():(1==lII&&"/"!==i.pathname&&"/favicon.ico"!==i.pathname&&await sendTelegramNotification("#异常访问 "+IlIl,r.headers.get("CF-Connecting-IP"),`UA: ${d}</tg-spoiler>
域名: ${i.hostname}
<tg-spoiler>入口: ${i.pathname+i.search}</tg-spoiler>`),u.URL302?Response.redirect(u.URL302,302):u.URL?proxyURL(u.URL,i):renderNginxPage());{await sendTelegramNotification("#获取订阅 "+IlIl,r.headers.get("CF-Connecting-IP"),`UA: ${c}</tg-spoiler>
域名: ${i.hostname}
<tg-spoiler>入口: ${i.pathname+i.search}</tg-spoiler>`);let t="base64";d.includes("null")||d.includes("subconverter")||d.includes("nekobox")||d.includes("CF-Workers-SUB".toLowerCase())?t="base64":d.includes("clash")||i.searchParams.has("clash")&&!d.includes("subconverter")?t="clash":d.includes("sing-box")||d.includes("singbox")||(i.searchParams.has("sb")||i.searchParams.has("singbox"))&&!d.includes("subconverter")?t="singbox":d.includes("surge")||i.searchParams.has("surge")&&!d.includes("subconverter")?t="surge":d.includes("quantumult%20x")||i.searchParams.has("quanx")&&!d.includes("subconverter")?t="quanx":(d.includes("loon")||i.searchParams.has("loon")&&!d.includes("subconverter"))&&(t="loon");let l,e=`${i.origin}/${await doubleMD5Hash(p)}?token=`+p;f=IIll;let n="v2rayn";console.log("请求方: ",i.searchParams),i.searchParams.has("clash")?n="clash":i.searchParams.has("singbox")?n="singbox":i.searchParams.has("surge")?n="surge":i.searchParams.has("quanx")?n="Quantumult%20X":i.searchParams.has("loon")&&(n="Loon");a=await getSubscriptionData(lIli,r,n,c);f+=a[0].join("\n"),e+="|"+a[1],u.WARP&&(e+="|"+(await parseLinks(u.WARP)).join("|"));d=(new TextEncoder).encode(f),i=(new TextDecoder).decode(d),r=[...new Set(i.split("\n"))].join("\n");let o;try{o=btoa(r)}catch(e){o=encodeBase64(r)}if("base64"==t||s==p)return new Response(o,{headers:{"content-type":"text/plain; charset=utf-8","Profile-Update-Interval":""+lIil,"Subscription-Userinfo":`upload=${I}; download=${I}; llIl=${llIl}; expireTimeInSeconds=`+g}});switch(t){case"clash":l=`${llI}://${IlIIi}/sub?target=clash&url=${encodeURIComponent(e)}&insert=false&config=${encodeURIComponent(IilI)}&emoji=true&list=false&tfo=false&scv=true&fdn=false&sort=false&new_name=true`;break;case"singbox":l=`${llI}://${IlIIi}/sub?target=singbox&url=${encodeURIComponent(e)}&insert=false&config=${encodeURIComponent(IilI)}&emoji=true&list=false&tfo=false&scv=true&fdn=false&sort=false&new_name=true`;break;case"surge":l=`${llI}://${IlIIi}/sub?target=surge&url=${encodeURIComponent(e)}&insert=false&config=${encodeURIComponent(IilI)}&emoji=true&list=false&tfo=false&scv=true&fdn=false&sort=false&new_name=true`;break;case"quanx":l=`${llI}://${IlIIi}/sub?target=quanx&url=${encodeURIComponent(e)}&insert=false&config=${encodeURIComponent(IilI)}&emoji=true&list=false&tfo=false&scv=true&fdn=false&sort=false&udp=true`;break;case"loon":l=`${llI}://${IlIIi}/sub?target=loon&url=${encodeURIComponent(e)}&insert=false&config=${encodeURIComponent(IilI)}&emoji=true&list=false&tfo=false&scv=true&fdn=false&sort=false`;break;default:l=e}try{var m=await fetch(l);if(!m.ok)return new Response(o,{headers:{"content-type":"text/plain; charset=utf-8","Profile-Update-Interval":""+lIil,"Subscription-Userinfo":`upload=${I}; download=${I}; llIl=${llIl}; expireTimeInSeconds=`+g}});let e=await m.text();return"clash"==t&&(e=await fixClashConfig(e)),new Response(e,{headers:{"Content-Disposition":`attachment; filename*=utf-8''${encodeURIComponent(IlIl)}; filename=`+IlIl,"content-type":"text/plain; charset=utf-8","Profile-Update-Interval":""+lIil,"Subscription-Userinfo":`upload=${I}; download=${I}; llIl=${llIl}; expireTimeInSeconds=`+g}})}catch(e){return new Response(o,{headers:{"content-type":"text/plain; charset=utf-8","Profile-Update-Interval":""+lIil,"Subscription-Userinfo":`upload=${I}; download=${I}; llIl=${llIl}; expireTimeInSeconds=`+g}})}}}};async function parseLinks(e){let t=e.replace(/[	"'|\r\n]+/g,",").replace(/,+/g,",");return(t=","===(t=","===t.charAt(0)?t.slice(1):t).charAt(t.length-1)?t.slice(0,t.length-1):t).split(",")}async function sendTelegramNotification(t,l,n=""){if(""!==IlI&&""!==Iil){let e="";var o=await fetch(`http://ip-api.com/json/${l}?lang=zh-CN`),o=(e=200===o.status?`${t}
IP: ${l}
国家: ${(o=await o.json()).country}
<tg-spoiler>城市: ${o.city}
组织: ${o.org}
ASN: ${o.as}
`+n:t+`
IP: ${l}
<tg-spoiler>`+n,`https://api.telegram.org/bot${IlI}/sendMessage?chat_id=${Iil}&parse_mode=HTML&text=`+encodeURIComponent(e));return fetch(o,{method:"get",headers:{Accept:"text/html,application/xhtml+xml,application/xml;","Accept-Encoding":"gzip, deflate, br","User-Agent":"Mozilla/5.0 Chrome/90.0.4430.72"}})}}function base64Decode(e){e=new Uint8Array(atob(e).split("").map(e=>e.charCodeAt(0)));return new TextDecoder("utf-8").decode(e)}async function doubleMD5Hash(e){var t=new TextEncoder;try{var l=await crypto.subtle.digest("MD5",t.encode(e)),n=Array.from(new Uint8Array(l)).map(e=>e.toString(16).padStart(2,"0")).join("").slice(7,27),o=await crypto.subtle.digest("MD5",t.encode(n));return Array.from(new Uint8Array(o)).map(e=>e.toString(16).padStart(2,"0")).join("").toLowerCase()}catch(e){}return""}function fixClashConfig(l){if(l.includes("wireguard")&&!l.includes("remote-dns-resolve")){let e,t="";for(var n of e=l.includes("\r\n")?l.split("\r\n"):l.split("\n"))n.includes("type: wireguard")?t+=n.replace(new RegExp(", mtu: 1280, udp: true","g"),", mtu: 1280, remote-dns-resolve: true, udp: true")+"\n":t+=n+"\n";l=t}return l}async function proxyURL(e,t){var e=await parseLinks(e),e=e[Math.floor(Math.random()*e.length)],e=new URL(e),l=(console.log(e),e.protocol.slice(0,-1)||"https"),n=e.hostname;let o=e.pathname;e=e.search,"/"==o.charAt(o.length-1)&&(o=o.slice(0,-1)),l=l+"://"+n+(o+=t.pathname)+e,n=await fetch(l),t=new Response(n.body,{status:n.status,statusText:n.statusText,headers:n.headers});return t.headers.set("X-New-URL",l),t}async function getSubscriptionData(n,t,l,o){if(!n||0===n.length)return[];let e="",r="",a="",i=new AbortController;var s=setTimeout(()=>{i.abort()},2e3);try{var c,d,u,p=[];for(let e=0;e<n.length;e+=5){var I=n.slice(e,e+5),g=await Promise.allSettled(I.map(e=>getUrl(t,e,l,o).then(e=>e.ok?e.text():Promise.reject(e))));p.push(...g)}for(c of p.map((e,t)=>{var l;return"rejected"===e.status?(l=e.reason)&&"AbortError"===l.name?{status:"超时",content:null,apiUrl:n[t]}:(console.error(`请求失败: ${n[t]}, 错误信息: ${l.status} `+l.statusText),{status:"请求失败",content:null,apiUrl:n[t]}):{status:e.status,content:e.value,apiUrl:n[t]}}))"fulfilled"===c.status&&((d=await c.content||"null").includes("proxies")&&d.includes("proxy-groups")||d.includes("outbounds")&&d.includes("inbounds")?r+="|"+c.apiUrl:d.includes("://")?e+=d+"\n":isValidBase64(d)?e+=base64Decode(d)+"\n":(u="trojan://CMLiussss@127.0.0.1:8888?security=tls&allowInsecure=1&type=tcp&headerType=none#%E5%BC%82%E5%B8%B8%E8%AE%A2%E9%98%85%20"+c.apiUrl.split("://")[1].split("/")[0],console.log(u),a+=u+`
`))}catch(e){console.error("请求异常: "+e.message)}finally{clearTimeout(s)}return[await parseLinks(e+a),r]}async function getUrl(e,t,l,n){var o=new Headers(e.headers),l=(o.set("User-Agent",`v2rayN/${l} `+n),new Request(t,{method:e.method,headers:o,body:"GET"===e.method?null:e.body,redirect:"follow"}));return console.log("请求URL: "+t),console.log("请求头: "+JSON.stringify([...o])),console.log("请求方法: "+e.method),console.log("请求体: "+("GET"===e.method?null:e.body)),fetch(l)}function isValidBase64(e){return/^[A-Za-z0-9+/=]+$/.test(e)}function encodeBase64(e){var t=(new TextEncoder).encode(e);let l="";var n="ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";for(let e=0;e<t.length;e+=3){var o=t[e],r=t[e+1]||0,a=t[e+2]||0;l=(l=(l=(l+=n[o>>2])+n[(3&o)<<4|r>>4])+n[(15&r)<<2|a>>6])+n[63&a]}e=3-(t.length%3||3);return l.slice(0,l.length-e)+"==".slice(0,e)}async function renderManagePage(e){return new Response(`<!DOCTYPE html>
<html lang="zh-CN">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <link rel="icon" type="image/png" href="/favicon-96x96.png" sizes="96x96" />
    <link rel="icon" type="image/svg+xml" href="/favicon.svg" />
    <link rel="shortcut icon" href="/favicon.ico" />
    <link rel="apple-touch-icon" sizes="180x180" href="/apple-touch-icon.png" />
    <link rel="manifest" href="/site.webmanifest" />
    <title>聚合订阅器-配置项管理</title>
    <style>
        body {
            font-family: 'Arial', sans-serif;
            margin: 0;
            padding: 20px;
            background-color: #f8f9fa;
        }
        .container {
            max-width: 900px;
            margin: auto;
            background: #ffffff;
            padding: 40px;
            border-radius: 8px;
            box-shadow: 0 4px 10px rgba(0, 0, 0, 0.1);
        }
        h1 {
            text-align: center;
            color: #343a40;
            margin-bottom: 30px;
        }
        h2 {
            margin-top: 40px;
            color: #007bff;
            border-bottom: 2px solid #007bff;
            padding-bottom: 8px;
            font-size: 20px;
        }
        .form-group {
            margin-bottom: 25px;
            display: flex;
            flex-direction: column;
        }
        label {
            font-size: 16px;
            font-weight: bold;
            margin-bottom: 8px;
            color: #495057;
        }
        input, textarea, select {
            width: 100%;
            padding: 12px;
            margin-top: 8px;
            font-size: 16px;
            border: 1px solid #ced4da;
            border-radius: 8px;
            background-color: #f8f9fa;
        }
        textarea {
            resize: vertical;
            min-height: 100px;
        }
        button {
            padding: 12px 20px;
            background-color: #007bff;
            color: #fff;
            border: none;
            border-radius: 8px;
            cursor: pointer;
            font-size: 16px;
            transition: background-color 0.3s;
            margin-top: 15px;
        }
        button:hover {
            background-color: #0056b3;
        }
        .clear-btn {
          background-color: #dc3545;
          color: #fff;
          border: none;
          border-radius: 6px;
          cursor: pointer;
          height: 100%;
          box-sizing: border-box;
          padding: 12px;
          margin-top: 8px;
          font-size: 16px;
        }
        
        .clear-btn:hover {
          background-color: #c82333;
        }
        .form-group .input-group {
            display: flex;
            align-items: center;
        }
        .form-group .input-group input {
            flex: 1;
        }
        .form-group .input-group .clear-btn {
            margin-left: 10px;
        }
        table {
            width: 100%;
            margin-top: 30px;
            border-collapse: collapse;
        }
        th, td {
            padding: 12px;
            text-align: left;
            border: 1px solid #ced4da;
        }
        th {
            background-color: #f8f9fa;
        }
        td pre {
            white-space: pre-wrap;
            word-wrap: break-word;
        }
        .description {
            font-size: 14px;
            color: #6c757d;
            margin-top: 8px;
        }
        .category-title {
            font-size: 18px;
            color: #007bff;
            border-bottom: 2px solid #007bff;
            padding-bottom: 5px;
            margin-bottom: 15px;
        }

        /* 固定按钮容器 */
        .button-container {
            position: fixed;
            right: 20px;
            bottom: 20px;
            display: flex;
            flex-direction: column;
            gap: 10px;
        }
        .button-container button {
            padding: 10px 15px;
            background-color: #007bff;
            color: #fff;
            border: none;
            border-radius: 8px;
            cursor: pointer;
            font-size: 14px;
            box-shadow: 0 2px 4px rgba(0, 0, 0, 0.2);
            transition: background-color 0.3s;
        }
        .button-container button:hover {
            background-color: #0056b3;
        }
        .button-container .scroll-top-btn {
            background-color: #6c757d;
        }
        .button-container .scroll-top-btn:hover {
            background-color: #343a40;
        }
    </style>
</head>
<body>

<div class="container">
    <h1>配置项管理</h1>

    <!-- 用户授权设置 -->
    <div class="category-title">用户授权设置</div>
    <div class="form-group">
        <label for="lIl">用户访问的授权令牌 (lIl):</label>
        <div class="input-group">
            <input type="text" id="lIl" />
            <button class="clear-btn" onclick="clearValue('lIl')">清空</button>
        </div>
        <div class="description">通过 UUID 或自定义字符串生成，作为用户的访问令牌。</div>
    </div>
    <div class="form-group">
        <label for="IlI">Telegram Bot Token (IlI):</label>
        <div class="input-group">
            <input type="text" id="IlI" />
            <button class="clear-btn" onclick="clearValue('IlI')">清空</button>
        </div>
        <div class="description">用于推送通知的 Telegram 机器人 Token，可以为空。</div>
    </div>
    <div class="form-group">
        <label for="Iil">Telegram Chat ID (Iil):</label>
        <div class="input-group">
            <input type="text" id="Iil" />
            <button class="clear-btn" onclick="clearValue('Iil')">清空</button>
        </div>
        <div class="description">指定接收通知的 Telegram 会话 ID，可以为空。</div>
    </div>

    <!-- 启用 Telegram 推送 -->
    <div class="form-group">
        <label for="lII">启用 Telegram 推送 (lII):</label>
        <select id="lII">
            <option value="1">推送所有访问信息</option>
            <option value="0">仅推送异常访问</option>
        </select>
        <div class="description">选择是否启用 Telegram 推送通知。</div>
    </div>

    <!-- 订阅设置 -->
    <div class="category-title">订阅设置</div>
    <div class="form-group">
        <label for="IlIl">自定义订阅文件名 (IlIl):</label>
        <div class="input-group">
            <input type="text" id="IlIl" />
            <button class="clear-btn" onclick="clearValue('IlIl')">清空</button>
        </div>
        <div class="description">设置自定义的订阅文件名。</div>
    </div>
    <div class="form-group">
        <label for="lIil">自定义订阅更新时间 (lIil):</label>
        <div class="input-group">
            <input type="number" id="lIil" />
            <button class="clear-btn" onclick="clearValue('lIil')">清空</button>
        </div>
        <div class="description">设置自定义的订阅更新时间，单位为小时。</div>
    </div>

    <!-- 流量和到期设置 -->
    <div class="category-title">流量与到期设置</div>
    <div class="form-group">
        <label for="llIl">节点流量 (llIl):</label>
        <div class="input-group">
            <input type="text" id="llIl" />
            <button class="clear-btn" onclick="clearValue('llIl')">清空</button>
        </div>
        <div class="description">设置节点流量，单位为 TB。</div>
    </div>
    <div class="form-group">
        <label for="IlII">节点到期时间 (IlII):</label>
        <div class="input-group">
            <input type="number" id="IlII" />
            <button class="clear-btn" onclick="clearValue('IlII')">清空</button>
        </div>
        <div class="description">设置节点到期时间，时间戳格式。</div>
    </div>

    <!-- 配置链接 -->
    <div class="category-title">配置链接设置</div>
    <div class="form-group">
        <label for="IIll">订阅聚合信息:</label>
        <div class="input-group">
            <textarea id="IIll"></textarea>
            <button class="clear-btn" onclick="clearValue('IIll')">清空</button>
        </div>
        <div class="description">包含节点链接和自定义订阅数据。ps. 通过换行来分割</div>
    </div>
    <div class="form-group">
        <label for="lIli">订阅链接 (lIli):</label>
        <div class="input-group">
            <input type="text" id="lIli" />
            <button class="clear-btn" onclick="clearValue('lIli')">清空</button>
        </div>
        <div class="description">存储用户的节点和订阅链接。</div>
    </div>
    <div class="form-group">
        <label for="IlIIi">订阅转换后端 API (IlIIi):</label>
        <div class="input-group">
            <input type="text" id="IlIIi" />
            <button class="clear-btn" onclick="clearValue('IlIIi')">清空</button>
        </div>
        <div class="description">在线订阅转换后端的 API 地址。</div>
    </div>
    <div class="form-group">
        <label for="IilI">订阅配置文件 URL (IilI):</label>
        <div class="input-group">
            <input type="text" id="IilI" />
            <button class="clear-btn" onclick="clearValue('IilI')">清空</button>
        </div>
        <div class="description">订阅配置文件的 URL。</div>
    </div>
    <div class="form-group">
        <label for="llI">订阅转换服务协议 (llI):</label>
        <div class="input-group">
            <input type="text" id="llI" />
            <button class="clear-btn" onclick="clearValue('llI')">清空</button>
        </div>
        <div class="description">支持 http 或 https。</div>
    </div>

    <!-- WARP 和 URL 设置 -->
    <div class="category-title">WARP 与 URL 设置</div>
    <div class="form-group">
        <label for="warp">是否使用 WARP 服务 (WARP):</label>
        <div class="input-group">
            <input type="text" id="warp" />
            <button class="clear-btn" onclick="clearValue('warp')">清空</button>
        </div>
        <div class="description">是否使用 WARP 服务，具体用途不明确。</div>
    </div>
    <div class="form-group">
        <label for="url302">302 重定向 URL (URL302):</label>
        <div class="input-group">
            <input type="text" id="url302" />
            <button class="clear-btn" onclick="clearValue('url302')">清空</button>
        </div>
        <div class="description">302 重定向的 URL。</div>
    </div>
    <div class="form-group">
        <label for="url">备用 URL (URL):</label>
        <div class="input-group">
            <input type="text" id="url" />
            <button class="clear-btn" onclick="clearValue('url')">清空</button>
        </div>
        <div class="description">备用 URL。</div>
    </div>
</div>

<!-- 固定按钮 -->
<div class="button-container">
    <button id="saveBtn">保存配置</button>
    <button id="scrollTopBtn" class="scroll-top-btn">回到顶部</button>
</div>

<script>
    // 清空指定的输入框
    function clearValue(id) {
        document.getElementById(id).value = '';
    }

    async function fetchVariables() {
      try {
          const response = await fetch('api/variables');
          const data = await response.json();
          const variables = JSON.parse(data.variables || "{}");

          // 默认值
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
              IilI: 'https://raw.githubusercontent.com/cmliu/ACL4SSR/main/Clash/config/ACL4SSR_Online_MultiCountry.ini',
              llI: 'https',
          };

		  let newData = Object.assign({}, defaultValues, variables);
  
          // 填充数据到输入框，如果 data 中不存在则用默认值
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

    // 回到顶部功能
    document.getElementById('scrollTopBtn').onclick = () => {
        window.scrollTo({ top: 0, behavior: 'smooth' });
    };
  

    // 保存修改
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

    // 页面加载时获取并填充数据
    window.onload = fetchVariables;
</script>

</body>
</html>
`,{headers:{"Content-Type":"text/html; charset=UTF-8"}})}async function renderLoginPage(){return new Response(`
    <!DOCTYPE html>
    <html lang="zh-CN">
    <head>
      <meta charset="UTF-8">
      <meta name="viewport" content="width=device-width, initial-scale=1.0">
      <link rel="icon" type="image/png" href="/favicon-96x96.png" sizes="96x96" />
      <link rel="icon" type="image/svg+xml" href="/favicon.svg" />
      <link rel="shortcut icon" href="/favicon.ico" />
      <link rel="apple-touch-icon" sizes="180x180" href="/apple-touch-icon.png" />
      <link rel="manifest" href="/site.webmanifest" />
      <title>登录</title>
      <style>
        body {
          font-family: Arial, sans-serif;
          margin: 0;
          padding: 0;
          display: flex;
          justify-content: center;
          align-items: center;
          height: 100vh;
          background: linear-gradient(135deg, #74ebd5, #acb6e5);
          overflow: hidden;
        }
        .login-container {
          background: #fff;
          padding: 30px;
          border-radius: 10px;
          box-shadow: 0 4px 20px rgba(0, 0, 0, 0.2);
          text-align: center;
          width: 350px;
          animation: fadeIn 1s ease-in-out;
        }
        .login-container h1 {
          margin-bottom: 20px;
          color: #333;
          font-size: 24px;
        }
        .login-container input {
          width: 100%;
          padding: 12px;
          margin-bottom: 15px;
          border: 1px solid #ccc;
          border-radius: 5px;
          font-size: 16px;
          transition: border-color 0.3s ease;
          box-sizing: border-box;
        }
        .login-container input:focus {
          border-color: #007bff;
          outline: none;
        }
        .login-container button {
          width: 100%;
          padding: 12px;
          background-color: #007bff;
          color: #fff;
          border: none;
          border-radius: 5px;
          font-size: 16px;
          cursor: pointer;
          transition: background-color 0.3s ease;
        }
        .login-container button:hover {
          background-color: #0056b3;
        }
        .login-container .error {
          color: red;
          margin-top: 10px;
          font-size: 14px;
          display: none;
        }
        @keyframes fadeIn {
          from { opacity: 0; transform: scale(0.9); }
          to { opacity: 1; transform: scale(1); }
        }
      </style>
    </head>
    <body>
      <div class="login-container">
        <h1>欢迎登录</h1>
        <input type="password" id="password" placeholder="请输入密码">
        <button onclick="login()">登录</button>
        <p id="error" class="error">密码错误，请重试！</p>
      </div>
      <script>
        async function login() {
          const password = document.getElementById('password').value;
          const errorElement = document.getElementById('error');
          errorElement.style.display = 'none';

          try {
            const response = await fetch('/login', {
              method: 'POST',
              headers: { 'Content-Type': 'application/json' },
              body: JSON.stringify({ password })
            });

            if (response.ok) {
              window.location.href = '/manage';
            } else {
              errorElement.style.display = 'block';
            }
          } catch (error) {
            errorElement.textContent = '登录失败，请稍后再试！';
            errorElement.style.display = 'block';
          }
        }
      </script>
    </body>
    </html>
  `,{headers:{"Content-Type":"text/html; charset=UTF-8"}})}async function renderNginxPage(){return new Response(`
  <!DOCTYPE html>
<html lang="zh-CN">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <link rel="icon" type="image/png" href="/favicon-96x96.png" sizes="96x96" />
  <link rel="icon" type="image/svg+xml" href="/favicon.svg" />
  <link rel="shortcut icon" href="/favicon.ico" />
  <link rel="apple-touch-icon" sizes="180x180" href="/apple-touch-icon.png" />
  <link rel="manifest" href="/site.webmanifest" />
  <title>网站维护中</title>
  <style>
    body {
      font-family: 'Arial', sans-serif;
      margin: 0;
      padding: 0;
      background-color: #f4f4f4;
      color: #333;
      display: flex;
      justify-content: center;
      align-items: center;
      height: 100vh;
      position: relative;
    }
    .container {
      width: 50%;
      background: #fff;
      box-shadow: 0 4px 6px rgba(0, 0, 0, 0.1);
      border-radius: 8px;
      padding: 30px;
      text-align: center;
      opacity: 0;
      transform: translateY(50px);
      transition: opacity 1s, transform 1s;
    }
    .container.visible {
      opacity: 1;
      transform: translateY(0);
    }
    .container h1 {
      font-size: 2rem;
      margin-bottom: 10px;
      color: #d9534f;
    }
    .container .message {
      font-size: 1.2rem;
      color: #555;
      margin-bottom: 20px;
    }
    footer {
      margin-top: 20px;
      font-size: 0.9rem;
      color: #aaa;
    }
    .corner {
      position: absolute;
      width: 50px;
      height: 50px;
      background-color: transparent;
      z-index: 10;
      cursor: pointer;
    }
    .corner-top-left { top: 0; left: 0; }
    .corner-top-right { top: 0; right: 0; }
    .corner-bottom-left { bottom: 0; left: 0; }
    .corner-bottom-right { bottom: 0; right: 0; }
  </style>
</head>
<body>
  <div class="container" id="content">
    <h1>网站暂时关闭</h1>
    <div class="message">由于当前网站受到大规模 DDoS 攻击，暂时关闭访问。</div>
    <footer>
      © <span id="currentYear"></span> 网站运营团队
    </footer>
  </div>

  <!-- 四个角的点击区域 -->
  <div class="corner corner-top-left" id="corner1" onclick="registerClick(1)"></div>
  <div class="corner corner-top-right" id="corner2" onclick="registerClick(2)"></div>
  <div class="corner corner-bottom-right" id="corner3" onclick="registerClick(3)"></div>
  <div class="corner corner-bottom-left" id="corner4" onclick="registerClick(4)"></div>

  <script>
    // 初始化年份
    document.getElementById("currentYear").textContent = new Date().getFullYear();

    let clickedCorners = [];
    let expectedOrder = [];
    let firstCorner = null;

    function registerClick(cornerId) {
      if (expectedOrder.length === 0) {
        firstCorner = cornerId;
        expectedOrder = generateOrder(firstCorner);
        // console.log("生成顺序:", expectedOrder);
      }

      if (cornerId === expectedOrder[clickedCorners.length]) {
        clickedCorners.push(cornerId);

        if (clickedCorners.length === 4) {
          // alert("成功！即将进入管理页面...");
          window.location.href = '/manage';
        }
      } else {
        resetClicks();
      }
    }

    function resetClicks() {
      // alert("点击顺序错误，请重新开始！");
      clickedCorners = [];
      expectedOrder = [];
      firstCorner = null;
    }

    function generateOrder(startCorner) {
      const corners = [1, 2, 3, 4];
      const index = corners.indexOf(startCorner);
    
      if (index === -1) {
        // console.error("起始角落非法");
        return [];
      }
    
      // 动态生成顺序：从起始点开始，顺时针或逆时针
      const today = new Date().getDate();
      let order;
      if (today % 2 === 0) {
        // 偶数日期，从起始点开始逆时针
        order = [startCorner].concat(corners.slice(0, index).reverse()).concat(corners.slice(index + 1).reverse());
      } else {
        // 奇数日期，从起始点开始顺时针
        order = [startCorner].concat(corners.slice(index + 1)).concat(corners.slice(0, index + 1));
      }
    
      return order;
    }

    window.onload = function() {
      document.getElementById('content').classList.add('visible');
    };
  </script>
</body>
</html>
  `,{headers:{"Content-Type":"text/html; charset=UTF-8"}})}async function handleLogin(e,t){var e=(await e.json()).password;return e===t.PWD?(e=new Date(Date.now()+36e5).toUTCString(),t=await generateToken(""+Date.now(),t.SECRET),new Response("登录成功！",{status:200,headers:{"Set-Cookie":`auth=${t}; Expires=${e}; Max-Age=3600; HttpOnly; Secure; Path=/`,"Content-Type":"application/json"}})):new Response("密码错误！",{status:401,headers:{"Content-Type":"text/plain"}})}async function handleVariablesAPI(e,t){var l=e.method,n=t.CONFIG_KV;if("GET"===l){var o,r={};for(o of(await n.list()).keys)r[o.name]=await n.get(o.name);return new Response(JSON.stringify(r),{headers:{"Content-Type":"application/json"}})}if("POST"!==l)return"DELETE"===l?(t=new URL(e.url).searchParams.get("key"))?(await n.delete(t),new Response("OK")):new Response("Bad Request",{status:400}):new Response("Method Not Allowed",{status:405});var a,i,l=await e.json();if("object"!=typeof l||null===l||0===Object.keys(l).length)return new Response("Bad Request: The request body should be an object with key-value pairs.",{status:400});for([a,i]of Object.entries(l)){if(!a||!i)return new Response("Bad Request: Each key and value must be non-empty.",{status:400});await n.put(a,JSON.stringify(i))}return new Response("OK")}