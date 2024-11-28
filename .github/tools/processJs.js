const fs = require('fs');
const { minify } = require('html-minifier');
const terser = require('terser');

// 读取原始文件
let content;
try {
  content = fs.readFileSync('source.js', 'utf8');
} catch (error) {
  console.error('读取文件失败:', error.message);
  process.exit(1);
}

// 清理注释
const withoutComments = content.replace(/\/\/.*|\/\*[\s\S]*?\*\//g, '');

// 定义变量名映射
const variableMap = {
  userToken: 'lIl',
  telegramBotToken: 'IlI',
  telegramChatID: 'Iil',
  enableTgPush: 'lII',
  subscriptionFileName: 'IlIl',
  subscriptionUpdateInterval: 'lIil',
  totalTraffic: 'llIl',
  expirationTimestamp: 'IlII',
  aggregatedSubscriptionData: 'IIll',
  subscriptionLinks: 'lIli',
  subscriptionConverterAPI: 'IlIIi',
  subscriptionConfigURL: 'IilI',
  converterProtocol: 'llI',
};

// 变量名称混淆
let obfuscated = withoutComments;
for (const [original, obfuscatedName] of Object.entries(variableMap)) {
  obfuscated = obfuscated.replace(new RegExp(`\\b${original}\\b`, 'g'), obfuscatedName);
}

// 压缩 HTML
const withMinifiedHTML = obfuscated.replace(/return new Response\(`([\s\S]*?)`,/g, (match, html) => {
  try {
    const minified = minify(html, {
      collapseWhitespace: true,
      removeComments: true,
      removeAttributeQuotes: true,
      minifyCSS: true,
      minifyJS: true,
    });
    return `return new Response(\`${minified}\`,`;
  } catch (error) {
    console.error('HTML 压缩失败:', error.message);
    return match; // 保留原始 HTML 以免程序崩溃
  }
});


// 压缩 JavaScript
let minifiedJS;
try {
  minifiedJS = terser.minify(withMinifiedHTML).code;
} catch (error) {
  console.error('JavaScript 压缩失败:', error.message);
  process.exit(1);
}

// 写入新的文件
try {
  fs.writeFileSync('work.js', minifiedJS);
  console.log('文件处理完成并保存为 work.js');
} catch (error) {
  console.error('写入文件失败:', error.message);
}
