let userToken = 'auto'; // 用户访问的授权令牌，可通过 UUID 或自定义字符串生成

// Telegram 机器人
// Telegram 机器人 Token，用于推送通知,可以为空
// 获取方法: @BotFather中输入/start，/newbot，并关注机器人
let telegramBotToken = '';
// Telegram Chat ID，用于指定接收通知的会话, 可以为空
// 获取方法: @userinfobot中获取，/start
let telegramChatID = '';
// 是否启用推送功能
// 1 为推送所有的访问信息，0 为不推送订阅转换后端的访问信息与异常访问
let enableTgPush = 0;

// 自定义订阅
let subscriptionFileName = 'CF-Workers-SUB';
let subscriptionUpdateInterval = 6; //自定义订阅更新时间，单位小时

// 节点流量与到期时间
let totalTraffic = 99;//TB
let expirationTimestamp = 4102329600000;//2099-12-31

// 多个订阅源和节点的聚合信息
let aggregatedSubscriptionData = ""

let subscriptionLinks = []; // 存储用户的节点和订阅链接
let subscriptionConverterAPI = "SUBAPI.fxxk.dedyn.io"; //在线订阅转换后端，目前使用CM的订阅转换功能。支持自建psub 可自行搭建https://github.com/bulianglin/psub
let subscriptionConfigURL = "https://raw.githubusercontent.com/cmliu/ACL4SSR/main/Clash/config/ACL4SSR_Online_MultiCountry.ini"; //订阅配置文件
let converterProtocol = 'https'; // 订阅转换服务协议（http 或 https）

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

  // 使用 Web 平台的 Base64 编码
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

  // 使用 Web API 解码 Base64 签名
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

  // 校验 Token 的签名
  const payload = await verifyToken(token, env.SECRET);
  if (!payload) return false;

  // 校验 Token 的有效期
  const timestamp = parseInt(payload, 10);
  const now = Date.now();
  const maxAge = 3600 * 1000; // 1小时（以毫秒为单位）

  if (now - timestamp > maxAge) return false;

  return true;
}


export default {
  async fetch(request, env) {
    // 获取请求头中的 User-Agent 信息并进行小写化处理
    const userAgentHeader = request.headers.get('User-Agent');
    const userAgent = userAgentHeader ? userAgentHeader.toLowerCase() : "null";

    // 解析请求的 URL 和 token
    const url = new URL(request.url);
    const token = url.searchParams.get('token');

    // 获取KV
    const kv = env.CONFIG_KV
    // 获取KV的数据
    let _variables = await kv.get("variables")
    const variables = _variables ? JSON.parse(_variables) : {}

    // 获取变量值
    userToken = variables.userToken || userToken;
    telegramBotToken = variables.telegramBotToken || telegramBotToken;
    telegramChatID = variables.telegramChatID || telegramChatID;
    enableTgPush = variables.enableTgPush || enableTgPush;
    subscriptionConverterAPI = variables.subscriptionConverterAPI || subscriptionConverterAPI;
    subscriptionConfigURL = variables.subscriptionConfigURL || subscriptionConfigURL;
    subscriptionFileName = variables.subscriptionFileName || subscriptionFileName;
    aggregatedSubscriptionData = variables.aggregatedSubscriptionData || aggregatedSubscriptionData;

    // 处理订阅链接（需要解析）
    if (variables.subscriptionLinks) subscriptionLinks = await parseLinks(variables.subscriptionLinks);

    if (subscriptionConverterAPI.includes("http://")) {
      subscriptionConverterAPI = subscriptionConverterAPI.split("//")[1];
      converterProtocol = 'http';
    } else {
      subscriptionConverterAPI = subscriptionConverterAPI.split("//")[1] || subscriptionConverterAPI;
    }

    // 获取当前日期零点的时间戳（秒）
    let todayTimestamp = Math.ceil(new Date().setHours(0, 0, 0, 0) / 1000);

    // 生成伪 token
    const generatedToken = await doubleMD5Hash(`${userToken}${todayTimestamp}`);

    // 计算可用流量和到期时间
    totalTraffic = totalTraffic * 1099511627776;
    let availableTraffic = Math.floor(((expirationTimestamp - Date.now()) / expirationTimestamp) * totalTraffic / 2); // 可用流量
    let expireTimeInSeconds = Math.floor(expirationTimestamp / 1000); // 到期时间（秒）

    subscriptionUpdateInterval = variables.subscriptionUpdateInterval || subscriptionUpdateInterval;

    let combinedLinks = await parseLinks(aggregatedSubscriptionData + '\n' + subscriptionLinks.join('\n'));
    let selfNodes = "";
    let subscriptionLinksStr = "";
    for (let x of combinedLinks) {
      if (x.toLowerCase().startsWith('http')) {
        subscriptionLinksStr += x + '\n';
      } else {
        selfNodes += x + '\n';
      }
    }
    aggregatedSubscriptionData = selfNodes;
    subscriptionLinks = await parseLinks(subscriptionLinksStr);

    if (!(token == userToken || token == generatedToken || url.pathname == ("/" + userToken) || url.pathname.includes("/" + userToken + "?"))) {

      // 处理登录请求
      if (url.pathname === "/login" && request.method === "POST") {
        return await handleLogin(request, env);
      }

      // 验证用户登录状态
      if (url.pathname === "/manage") {
        const authenticated = await isAuthenticated(request, env);
        if (!authenticated) {
          return await renderLoginPage();
        }

        return await renderManagePage(env); // 用户已登录，返回管理页面
      }

      // API 路径
      if (url.pathname === "/api/variables") {
        const authenticated = await isAuthenticated(request, env);
        if (!authenticated) {
          return await renderNginxPage()
        }
        return await handleVariablesAPI(request, env);
      }

      if (enableTgPush == 1 && url.pathname !== "/" && url.pathname !== "/favicon.ico") {
        await sendTelegramNotification(`#异常访问 ${subscriptionFileName}`, request.headers.get('CF-Connecting-IP'), `UA: ${userAgent}</tg-spoiler>\n域名: ${url.hostname}\n<tg-spoiler>入口: ${url.pathname + url.search}</tg-spoiler>`);
      }

      if (variables.URL302) {
        return Response.redirect(variables.URL302, 302);
      } else if (variables.URL) {
        return await proxyURL(variables.URL, url);
      } else {
        return await renderNginxPage()
      }

    } else {
      // 正常情况下发送 Telegram 通知
      await sendTelegramNotification(`#获取订阅 ${subscriptionFileName}`, request.headers.get('CF-Connecting-IP'), `UA: ${userAgentHeader}</tg-spoiler>\n域名: ${url.hostname}\n<tg-spoiler>入口: ${url.pathname + url.search}</tg-spoiler>`);

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

      // 构造请求订阅的响应内容
      let requestData = aggregatedSubscriptionData;
      let appendUA = 'v2rayn';
      if (url.searchParams.has('clash')) appendUA = 'clash';
      else if (url.searchParams.has('singbox')) appendUA = 'singbox';
      else if (url.searchParams.has('surge')) appendUA = 'surge';
      else if (url.searchParams.has('quanx')) appendUA = 'Quantumult%20X';
      else if (url.searchParams.has('loon')) appendUA = 'Loon';

      const subscriptionResponse = await getSubscriptionData(subscriptionLinks, request, appendUA, userAgentHeader);
      requestData += subscriptionResponse[0].join('\n');
      subscriptionConversionURL += "|" + subscriptionResponse[1];

      if (variables.WARP) {
        subscriptionConversionURL += "|" + (await parseLinks(variables.WARP)).join("|");
      }


      // 修复中文错误并处理编码
      const utf8Encoder = new TextEncoder();
      const encodedData = utf8Encoder.encode(requestData);
      const utf8Decoder = new TextDecoder();
      const text = utf8Decoder.decode(encodedData);

      // 去重并生成订阅内容
      const uniqueLines = new Set(text.split('\n'));
      const result = [...uniqueLines].join('\n');

      let base64Data;
      try {
        base64Data = btoa(result);
      } catch (e) {
        base64Data = encodeBase64(result);
      }

      // 根据订阅格式返回不同响应
      if (subscriptionFormat == 'base64' || token == generatedToken) {
        return new Response(base64Data, {
          headers: {
            "content-type": "text/plain; charset=utf-8",
            "Profile-Update-Interval": `${subscriptionUpdateInterval}`,
            "Subscription-Userinfo": `upload=${availableTraffic}; download=${availableTraffic}; totalTraffic=${totalTraffic}; expireTimeInSeconds=${expireTimeInSeconds}`,
          }
        });
      } else {
        // 转换为目标格式（Clash, Singbox等）
        let conversionURL;
        switch (subscriptionFormat) {
          case 'clash':
            conversionURL = `${converterProtocol}://${subscriptionConverterAPI}/sub?target=clash&url=${encodeURIComponent(subscriptionConversionURL)}&insert=false&config=${encodeURIComponent(subscriptionConfigURL)}&emoji=true&list=false&tfo=false&scv=true&fdn=false&sort=false&new_name=true`;
            break;
          case 'singbox':
            conversionURL = `${converterProtocol}://${subscriptionConverterAPI}/sub?target=singbox&url=${encodeURIComponent(subscriptionConversionURL)}&insert=false&config=${encodeURIComponent(subscriptionConfigURL)}&emoji=true&list=false&tfo=false&scv=true&fdn=false&sort=false&new_name=true`;
            break;
          case 'surge':
            conversionURL = `${converterProtocol}://${subscriptionConverterAPI}/sub?target=surge&url=${encodeURIComponent(subscriptionConversionURL)}&insert=false&config=${encodeURIComponent(subscriptionConfigURL)}&emoji=true&list=false&tfo=false&scv=true&fdn=false&sort=false&new_name=true`;
            break;
          case 'quanx':
            conversionURL = `${converterProtocol}://${subscriptionConverterAPI}/sub?target=quanx&url=${encodeURIComponent(subscriptionConversionURL)}&insert=false&config=${encodeURIComponent(subscriptionConfigURL)}&emoji=true&list=false&tfo=false&scv=true&fdn=false&sort=false&udp=true`;
            break;
          case 'loon':
            conversionURL = `${converterProtocol}://${subscriptionConverterAPI}/sub?target=loon&url=${encodeURIComponent(subscriptionConversionURL)}&insert=false&config=${encodeURIComponent(subscriptionConfigURL)}&emoji=true&list=false&tfo=false&scv=true&fdn=false&sort=false`;
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
              "Profile-Update-Interval": `${subscriptionUpdateInterval}`,
              "Subscription-Userinfo": `upload=${availableTraffic}; download=${availableTraffic}; totalTraffic=${totalTraffic}; expireTimeInSeconds=${expireTimeInSeconds}`,
            }
          });
          //throw new Error(`Error fetching subconverterUrl: ${subconverterResponse.status} ${subconverterResponse.statusText}`);
        }
        let subconverterContent = await subconverterResponse.text();
        if (subscriptionFormat == 'clash') subconverterContent = await fixClashConfig(subconverterContent);
        return new Response(subconverterContent, {
          headers: {
            "Content-Disposition": `attachment; filename*=utf-8''${encodeURIComponent(subscriptionFileName)}; filename=${subscriptionFileName}`,
            "content-type": "text/plain; charset=utf-8",
            "Profile-Update-Interval": `${subscriptionUpdateInterval}`,
            "Subscription-Userinfo": `upload=${availableTraffic}; download=${availableTraffic}; totalTraffic=${totalTraffic}; expireTimeInSeconds=${expireTimeInSeconds}`,

          },
        });
      } catch (error) {
        return new Response(base64Data, {
          headers: {
            "content-type": "text/plain; charset=utf-8",
            "Profile-Update-Interval": `${subscriptionUpdateInterval}`,
            "Subscription-Userinfo": `upload=${availableTraffic}; download=${availableTraffic}; totalTraffic=${totalTraffic}; expireTimeInSeconds=${expireTimeInSeconds}`,
          }
        });
      }
    }
  }
};

/**
 * 将订阅链接按换行符、逗号或其他分隔符解析为数组
 * 该函数会清理输入的字符串，将换行符、空格、引号等转换为逗号，并按逗号分隔成数组
 * @param {string} subscriptionLinks - 需要解析的订阅链接字符串
 * @returns {Promise<string[]>} - 返回解析后的字符串数组
 */
async function parseLinks(subscriptionLinks) {
  // 清理输入，替换空格、双引号、单引号和换行符为逗号
  let cleanedText = subscriptionLinks.replace(/[	"'|\r\n]+/g, ',').replace(/,+/g, ',');

  // 如果字符串以逗号开头或结尾，去除这些多余的逗号
  if (cleanedText.charAt(0) === ',') cleanedText = cleanedText.slice(1);
  if (cleanedText.charAt(cleanedText.length - 1) === ',') cleanedText = cleanedText.slice(0, cleanedText.length - 1);

  // 按逗号分隔字符串并返回数组
  const resultArray = cleanedText.split(',');

  return resultArray;
}




/**
 * 通过 Telegram 推送通知，包含 IP 信息及访问详情
 * 获取 IP 地址的地理信息并将其发送至 Telegram
 * @param {string} type - 通知的类型或标题
 * @param {string} ip - 目标 IP 地址
 * @param {string} [add_data=""] - 额外的附加数据（可选）
 * @returns {Promise<Response>} - Telegram API 的响应
 */
async function sendTelegramNotification(type, ip, add_data = "") {
  // 确保 Telegram bot Token 和 Chat ID 都已经配置
  if (telegramBotToken !== '' && telegramChatID !== '') {
    let msg = "";

    // 请求 IP 地址的地理信息
    const response = await fetch(`http://ip-api.com/json/${ip}?lang=zh-CN`);

    if (response.status === 200) {
      const ipInfo = await response.json();
      // 组装包含 IP 信息的消息
      msg = `${type}\nIP: ${ip}\n国家: ${ipInfo.country}\n<tg-spoiler>城市: ${ipInfo.city}\n组织: ${ipInfo.org}\nASN: ${ipInfo.as}\n${add_data}`;
    } else {
      // 如果无法获取 IP 信息，则只返回 IP 和附加数据
      msg = `${type}\nIP: ${ip}\n<tg-spoiler>${add_data}`;
    }

    // 构建 Telegram API 请求 URL
    let url = `https://api.telegram.org/bot${telegramBotToken}/sendMessage?chat_id=${telegramChatID}&parse_mode=HTML&text=${encodeURIComponent(msg)}`;

    // 发送 GET 请求到 Telegram API
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

/**
 * 执行两次 MD5 哈希生成伪授权令牌
 * 第一次哈希使用原始文本，第二次哈希使用第一次哈希值的部分作为输入
 * @param {string} text - 要进行哈希处理的原始文本
 * @returns {Promise<string>} - 生成的伪授权令牌（第二次 MD5 哈希结果）
 */
async function doubleMD5Hash(text) {
  // 创建一个文本编码器，将文本转换为字节
  const encoder = new TextEncoder();

  // 第一次 MD5 哈希
  const firstHash = await crypto.subtle.digest('MD5', encoder.encode(text));
  const firstHashArray = Array.from(new Uint8Array(firstHash));
  const firstHex = firstHashArray.map(byte => byte.toString(16).padStart(2, '0')).join('');

  // 取第一次哈希结果的第8到第28个字符进行第二次哈希
  const secondHashInput = firstHex.slice(7, 27);
  const secondHash = await crypto.subtle.digest('MD5', encoder.encode(secondHashInput));
  const secondHashArray = Array.from(new Uint8Array(secondHash));
  const secondHex = secondHashArray.map(byte => byte.toString(16).padStart(2, '0')).join('');

  // 返回第二次 MD5 哈希值的小写结果
  return secondHex.toLowerCase();
}

/**
 * 修复 Clash 配置中的兼容性问题
 * 主要是针对包含 wireguard 的配置，确保配置中有 remote-dns-resolve 和正确的 udp 设置
 * @param {string} configContent - 要修复的配置内容
 * @returns {string} 修复后的配置内容
 */
function fixClashConfig(configContent) {
  // 检查配置内容是否包含 'wireguard' 且未包含 'remote-dns-resolve'
  if (configContent.includes('wireguard') && !configContent.includes('remote-dns-resolve')) {
    let configLines;

    // 判断分隔符类型并拆分配置内容为行
    if (configContent.includes('\r\n')) {
      configLines = configContent.split('\r\n');
    } else {
      configLines = configContent.split('\n');
    }

    let updatedConfig = "";

    // 遍历每一行配置
    for (let line of configLines) {
      // 查找包含 'type: wireguard' 的行
      if (line.includes('type: wireguard')) {
        const legacyConfigPart = `, mtu: 1280, udp: true`; // 旧的配置部分
        const correctedConfigPart = `, mtu: 1280, remote-dns-resolve: true, udp: true`; // 正确的配置部分

        // 替换旧配置为正确配置
        updatedConfig += line.replace(new RegExp(legacyConfigPart, 'g'), correctedConfigPart) + '\n';
      } else {
        updatedConfig += line + '\n'; // 其他行不变
      }
    }

    // 将修复后的内容赋值回 content
    configContent = updatedConfig;
  }

  return configContent; // 返回修复后的配置内容
}


async function proxyURL(proxyURL, url) {
  const URLs = await parseLinks(proxyURL);
  const fullURL = URLs[Math.floor(Math.random() * URLs.length)];

  // 解析目标 URL
  let parsedURL = new URL(fullURL);
  console.log(parsedURL);
  // 提取并可能修改 URL 组件
  let URLProtocol = parsedURL.protocol.slice(0, -1) || 'https';
  let URLHostname = parsedURL.hostname;
  let URLPathname = parsedURL.pathname;
  let URLSearch = parsedURL.search;

  // 处理 pathname
  if (URLPathname.charAt(URLPathname.length - 1) == '/') {
    URLPathname = URLPathname.slice(0, -1);
  }
  URLPathname += url.pathname;

  // 构建新的 URL
  let newURL = `${URLProtocol}://${URLHostname}${URLPathname}${URLSearch}`;

  // 反向代理请求
  let response = await fetch(newURL);

  // 创建新的响应
  let newResponse = new Response(response.body, {
    status: response.status,
    statusText: response.statusText,
    headers: response.headers
  });

  // 添加自定义头部，包含 URL 信息
  //newResponse.headers.set('X-Proxied-By', 'Cloudflare Worker');
  //newResponse.headers.set('X-Original-URL', fullURL);
  newResponse.headers.set('X-New-URL', newURL);

  return newResponse;
}

/**
 * 从多个 API URL 获取订阅数据并对其进行处理。
 * 
 * 该函数接受一组 API URL，请求每个 URL 获取响应，并根据响应内容进行分类处理。它将返回有效的订阅内容和转换后的 URL。
 * 
 * @param {string[]} apiUrls - 要请求的 API URL 列表。每个 URL 将依次发送请求。
 * @param {Object} request - 请求的配置对象，用于设置请求头等信息。该对象将被传递给 `getUrl` 函数。
 * @param {string} appendUA - 是否在请求头中附加用户代理 (User-Agent) 信息。
 * @param {string} userAgentHeader - 要在请求中使用的用户代理字符串。
 * 
 * @returns {Promise<Array>} 返回一个包含两个元素的数组：
 * - 第一个元素是处理过的有效订阅内容（例如，base64 解码后的内容）。
 * - 第二个元素是已转换的 URL 列表，这些 URL 可用于不同的订阅配置（如 Clash 或 Singbox 配置）。
 * 
 * @throws {Error} 如果请求失败或响应处理出错，则抛出错误。
 */
async function getSubscriptionData(apiUrls, request, appendUA, userAgentHeader) {
  if (!apiUrls || apiUrls.length === 0) {
    return [];  // 如果没有提供 API 列表，直接返回空数组
  }

  let validApiResponses = "";  // 用于存储有效的 API 响应内容
  let convertedUrls = "";  // 用于存储已转换的订阅 URL
  let errorUrls = "";  // 用于存储错误的 URL

  const abortController = new AbortController();  // 创建一个 AbortController 实例，用于控制请求超时
  const timeoutId = setTimeout(() => {
    abortController.abort();  // 设置超时后取消所有请求
  }, 2000);

  try {
    // 限制并发请求数，避免过多请求导致性能问题
    const maxConcurrentRequests = 5; // 最大并发请求数
    const responses = [];

    // 批量请求 API，每批最多 maxConcurrentRequests 个请求
    for (let i = 0; i < apiUrls.length; i += maxConcurrentRequests) {
      const currentBatch = apiUrls.slice(i, i + maxConcurrentRequests);
      const batchResults = await Promise.allSettled(currentBatch.map(apiUrl =>
        getUrl(request, apiUrl, appendUA, userAgentHeader)
          .then(response => response.ok ? response.text() : Promise.reject(response))
      ));

      responses.push(...batchResults);  // 将当前批次的响应结果合并
    }

    // 处理所有 API 响应
    const processedResponses = responses.map((response, index) => {
      if (response.status === 'rejected') {
        const reason = response.reason;
        if (reason && reason.name === 'AbortError') {
          return { status: '超时', content: null, apiUrl: apiUrls[index] };  // 请求超时
        }
        console.error(`请求失败: ${apiUrls[index]}, 错误信息: ${reason.status} ${reason.statusText}`);
        return { status: '请求失败', content: null, apiUrl: apiUrls[index] };  // 请求失败
      }
      return { status: response.status, content: response.value, apiUrl: apiUrls[index] };  // 请求成功
    });

    // 解析每个响应并根据内容分类
    for (const response of processedResponses) {
      if (response.status === 'fulfilled') {
        const content = await response.content || 'null';  // 获取响应内容

        if (content.includes('proxies') && content.includes('proxy-groups')) {
          convertedUrls += "|" + response.apiUrl;  // Clash 配置
        } else if (content.includes('outbounds') && content.includes('inbounds')) {
          convertedUrls += "|" + response.apiUrl;  // Singbox 配置
        } else if (content.includes('://')) {
          validApiResponses += content + '\n';  // 追加有效 URL 响应内容
        } else if (isValidBase64(content)) {
          validApiResponses += base64Decode(content) + '\n';  // 解码并追加内容
        } else {
          const errorLink = `trojan://CMLiussss@127.0.0.1:8888?security=tls&allowInsecure=1&type=tcp&headerType=none#%E5%BC%82%E5%B8%B8%E8%AE%A2%E9%98%85%20${response.apiUrl.split('://')[1].split('/')[0]}`;
          console.log(errorLink);
          errorUrls += `${errorLink}\n`;  // 处理异常订阅链接
        }
      }
    }
  } catch (error) {
    console.error(`请求异常: ${error.message}`);  // 捕获并输出异常错误信息
  } finally {
    clearTimeout(timeoutId);  // 清除超时定时器
  }

  // 将有效的订阅内容与错误的 URL 合并，并将其传递给解析函数
  const subscriptionContent = await parseLinks(validApiResponses + errorUrls);
  return [subscriptionContent, convertedUrls];
}


async function getUrl(request, targetUrl, appendUA, userAgentHeader) {
  // 设置自定义 User-Agent
  const newHeaders = new Headers(request.headers);
  newHeaders.set("User-Agent", `v2rayN/${appendUA} cmliu/CF-Workers-SUB ${userAgentHeader}`);

  // 构建新的请求对象
  const modifiedRequest = new Request(targetUrl, {
    method: request.method,
    headers: newHeaders,
    body: request.method === "GET" ? null : request.body,
    redirect: "follow"
  });

  // 输出请求的详细信息
  console.log(`请求URL: ${targetUrl}`);
  console.log(`请求头: ${JSON.stringify([...newHeaders])}`);
  console.log(`请求方法: ${request.method}`);
  console.log(`请求体: ${request.method === "GET" ? null : request.body}`);

  // 发送请求并返回响应
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


// 渲染管理页面
async function renderManagePage(env) {
  return new Response(`<!DOCTYPE html>
<html lang="zh-CN">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <link rel="icon" type="image/png" href="/assets/favicon-96x96.png" sizes="96x96" />
    <link rel="icon" type="image/svg+xml" href="/assets/favicon.svg" />
    <link rel="shortcut icon" href="/assets/favicon.ico" />
    <link rel="apple-touch-icon" sizes="180x180" href="/assets/apple-touch-icon.png" />
    <link rel="manifest" href="/assets/site.webmanifest" />
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
        <label for="userToken">用户访问的授权令牌 (userToken):</label>
        <div class="input-group">
            <input type="text" id="userToken" />
            <button class="clear-btn" onclick="clearValue('userToken')">清空</button>
        </div>
        <div class="description">通过 UUID 或自定义字符串生成，作为用户的访问令牌。</div>
    </div>
    <div class="form-group">
        <label for="telegramBotToken">Telegram Bot Token (telegramBotToken):</label>
        <div class="input-group">
            <input type="text" id="telegramBotToken" />
            <button class="clear-btn" onclick="clearValue('telegramBotToken')">清空</button>
        </div>
        <div class="description">用于推送通知的 Telegram 机器人 Token，可以为空。</div>
    </div>
    <div class="form-group">
        <label for="telegramChatID">Telegram Chat ID (telegramChatID):</label>
        <div class="input-group">
            <input type="text" id="telegramChatID" />
            <button class="clear-btn" onclick="clearValue('telegramChatID')">清空</button>
        </div>
        <div class="description">指定接收通知的 Telegram 会话 ID，可以为空。</div>
    </div>

    <!-- 启用 Telegram 推送 -->
    <div class="form-group">
        <label for="enableTgPush">启用 Telegram 推送 (enableTgPush):</label>
        <select id="enableTgPush">
            <option value="1">推送所有访问信息</option>
            <option value="0">仅推送异常访问</option>
        </select>
        <div class="description">选择是否启用 Telegram 推送通知。</div>
    </div>

    <!-- 订阅设置 -->
    <div class="category-title">订阅设置</div>
    <div class="form-group">
        <label for="subscriptionFileName">自定义订阅文件名 (subscriptionFileName):</label>
        <div class="input-group">
            <input type="text" id="subscriptionFileName" />
            <button class="clear-btn" onclick="clearValue('subscriptionFileName')">清空</button>
        </div>
        <div class="description">设置自定义的订阅文件名。</div>
    </div>
    <div class="form-group">
        <label for="subscriptionUpdateInterval">自定义订阅更新时间 (subscriptionUpdateInterval):</label>
        <div class="input-group">
            <input type="number" id="subscriptionUpdateInterval" />
            <button class="clear-btn" onclick="clearValue('subscriptionUpdateInterval')">清空</button>
        </div>
        <div class="description">设置自定义的订阅更新时间，单位为小时。</div>
    </div>

    <!-- 流量和到期设置 -->
    <div class="category-title">流量与到期设置</div>
    <div class="form-group">
        <label for="totalTraffic">节点流量 (totalTraffic):</label>
        <div class="input-group">
            <input type="text" id="totalTraffic" />
            <button class="clear-btn" onclick="clearValue('totalTraffic')">清空</button>
        </div>
        <div class="description">设置节点流量，单位为 TB。</div>
    </div>
    <div class="form-group">
        <label for="expirationTimestamp">节点到期时间 (expirationTimestamp):</label>
        <div class="input-group">
            <input type="number" id="expirationTimestamp" />
            <button class="clear-btn" onclick="clearValue('expirationTimestamp')">清空</button>
        </div>
        <div class="description">设置节点到期时间，时间戳格式。</div>
    </div>

    <!-- 配置链接 -->
    <div class="category-title">配置链接设置</div>
    <div class="form-group">
        <label for="aggregatedSubscriptionData">订阅聚合信息:</label>
        <div class="input-group">
            <textarea id="aggregatedSubscriptionData"></textarea>
            <button class="clear-btn" onclick="clearValue('aggregatedSubscriptionData')">清空</button>
        </div>
        <div class="description">包含节点链接和自定义订阅数据。ps. 通过换行来分割</div>
    </div>
    <div class="form-group">
        <label for="subscriptionLinks">订阅链接 (subscriptionLinks):</label>
        <div class="input-group">
            <input type="text" id="subscriptionLinks" />
            <button class="clear-btn" onclick="clearValue('subscriptionLinks')">清空</button>
        </div>
        <div class="description">存储用户的节点和订阅链接。</div>
    </div>
    <div class="form-group">
        <label for="subscriptionConverterAPI">订阅转换后端 API (subscriptionConverterAPI):</label>
        <div class="input-group">
            <input type="text" id="subscriptionConverterAPI" />
            <button class="clear-btn" onclick="clearValue('subscriptionConverterAPI')">清空</button>
        </div>
        <div class="description">在线订阅转换后端的 API 地址。</div>
    </div>
    <div class="form-group">
        <label for="subscriptionConfigURL">订阅配置文件 URL (subscriptionConfigURL):</label>
        <div class="input-group">
            <input type="text" id="subscriptionConfigURL" />
            <button class="clear-btn" onclick="clearValue('subscriptionConfigURL')">清空</button>
        </div>
        <div class="description">订阅配置文件的 URL。</div>
    </div>
    <div class="form-group">
        <label for="converterProtocol">订阅转换服务协议 (converterProtocol):</label>
        <div class="input-group">
            <input type="text" id="converterProtocol" />
            <button class="clear-btn" onclick="clearValue('converterProtocol')">清空</button>
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
              userToken: 'auto',
              telegramBotToken: '',
              telegramChatID: '',
              enableTgPush: '0',
              subscriptionFileName: 'CF-Workers-SUB',
              subscriptionUpdateInterval: 6,
              totalTraffic: 99,
              expirationTimestamp: 4102329600000,
              aggregatedSubscriptionData: [],
              subscriptionLinks: [],
              subscriptionConverterAPI: 'SUBAPI.fxxk.dedyn.io',
              subscriptionConfigURL: 'https://raw.githubusercontent.com/cmliu/ACL4SSR/main/Clash/config/ACL4SSR_Online_MultiCountry.ini',
              converterProtocol: 'https',
          };

		  let newData = Object.assign({}, defaultValues, variables);
  
          // 填充数据到输入框，如果 data 中不存在则用默认值
          document.getElementById('userToken').value = newData.userToken;
          document.getElementById('telegramBotToken').value = newData.telegramBotToken;
          document.getElementById('telegramChatID').value = newData.telegramChatID;
          document.getElementById('enableTgPush').value = newData.enableTgPush;
          document.getElementById('subscriptionFileName').value = newData.subscriptionFileName;
          document.getElementById('subscriptionUpdateInterval').value = newData.subscriptionUpdateInterval;
          document.getElementById('totalTraffic').value = newData.totalTraffic;
          document.getElementById('expirationTimestamp').value = newData.expirationTimestamp;
          document.getElementById('aggregatedSubscriptionData').value = newData.aggregatedSubscriptionData.join("\\n");
          document.getElementById('subscriptionLinks').value = newData.subscriptionLinks;
          document.getElementById('subscriptionConverterAPI').value = newData.subscriptionConverterAPI;
          document.getElementById('subscriptionConfigURL').value = newData.subscriptionConfigURL;
          document.getElementById('converterProtocol').value = newData.converterProtocol;
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
            userToken: document.getElementById('userToken').value,
            telegramBotToken: document.getElementById('telegramBotToken').value,
            telegramChatID: document.getElementById('telegramChatID').value,
            enableTgPush: document.getElementById('enableTgPush').value,
            subscriptionFileName: document.getElementById('subscriptionFileName').value,
            subscriptionUpdateInterval: document.getElementById('subscriptionUpdateInterval').value,
            totalTraffic: document.getElementById('totalTraffic').value,
            expirationTimestamp: document.getElementById('expirationTimestamp').value,
            aggregatedSubscriptionData: document.getElementById('aggregatedSubscriptionData').value.split("\\n"),
            subscriptionLinks: document.getElementById('subscriptionLinks').value,
            subscriptionConverterAPI: document.getElementById('subscriptionConverterAPI').value,
            subscriptionConfigURL: document.getElementById('subscriptionConfigURL').value,
            converterProtocol: document.getElementById('converterProtocol').value,
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
`, { headers: { "Content-Type": "text/html; charset=UTF-8" } });
}

async function renderLoginPage() {
  return new Response(`
    <!DOCTYPE html>
    <html lang="zh-CN">
    <head>
      <meta charset="UTF-8">
      <meta name="viewport" content="width=device-width, initial-scale=1.0">
      <link rel="icon" type="image/png" href="/assets/favicon-96x96.png" sizes="96x96" />
      <link rel="icon" type="image/svg+xml" href="/assets/favicon.svg" />
      <link rel="shortcut icon" href="/assets/favicon.ico" />
      <link rel="apple-touch-icon" sizes="180x180" href="/assets/apple-touch-icon.png" />
      <link rel="manifest" href="/assets/site.webmanifest" />
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
  `, { headers: { "Content-Type": "text/html; charset=UTF-8" } });
}


/**
 * 返回默认 Nginx 欢迎页面内容
 * @returns
 */
async function renderNginxPage() {
  return new Response(`
  <!DOCTYPE html>
<html lang="zh-CN">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <link rel="icon" type="image/png" href="/assets/favicon-96x96.png" sizes="96x96" />
  <link rel="icon" type="image/svg+xml" href="/assets/favicon.svg" />
  <link rel="shortcut icon" href="/assets/favicon.ico" />
  <link rel="apple-touch-icon" sizes="180x180" href="/assets/apple-touch-icon.png" />
  <link rel="manifest" href="/assets/site.webmanifest" />
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
  `, { headers: { "Content-Type": "text/html; charset=UTF-8" } });
}

// 登录api
async function handleLogin(request, env) {
    const { password } = await request.json();

    if (password === env.PWD) {
      const maxAge = 3600; // 1小时
      const expires = new Date(Date.now() + maxAge * 1000).toUTCString();
  
      // 生成加密 Token
      const tokenPayload = `${Date.now()}`; // 使用时间戳作为有效负载
      const token = await generateToken(tokenPayload, env.SECRET);

      // return log({password, isok: password === env.PWD, token})
  
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
  


// 处理 API 请求
async function handleVariablesAPI(request, env) {
  const method = request.method;
  const kv = env.CONFIG_KV;

  if (method === "GET") {
    // 获取所有变量
    const keys = await kv.list();
    const data = {};
    for (const key of keys.keys) {
      data[key.name] = await kv.get(key.name);
    }
    return new Response(JSON.stringify(data), { headers: { "Content-Type": "application/json" } });
  } else if (method === "POST") {
    // 添加或更新多个变量
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
    // 删除变量
    const url = new URL(request.url);
    const key = url.searchParams.get("key");
    if (!key) return new Response("Bad Request", { status: 400 });
    await kv.delete(key);
    return new Response("OK");
  }

  return new Response("Method Not Allowed", { status: 405 });
}