const fs = require('fs');
const { minify } = require('html-minifier');
const UglifyJS = require('uglify-js');

// 读取文件内容
function readFile(filePath) {
  try {
    return fs.readFileSync(filePath, 'utf8');
  } catch (error) {
    console.error('读取文件失败:', error.message);
    process.exit(1);
  }
}

// 变量名称混淆
function obfuscateVariables(content, variableMap) {
  let obfuscated = content;
  for (const [original, obfuscatedName] of Object.entries(variableMap)) {
    obfuscated = obfuscated.replace(new RegExp(`\\b${original}\\b`, 'g'), obfuscatedName);
  }
  return obfuscated;
}

// 压缩 HTML
function minifyHTML(content) {
  return content.replace(/return new Response\(`([\s\S]*?)`,/g, (match, html) => {
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
}

// 使用 uglify-js 压缩代码
function minifyJS(content) {
  try {
    const result = UglifyJS.minify(content);
    if (result.error) {
      throw result.error;
    }
    return result.code;
  } catch (error) {
    console.error('JavaScript 压缩失败:', error.message);
    process.exit(1);
  }
}

// 写入文件
function writeFile(outputFilePath, content) {
  try {
    fs.writeFileSync(outputFilePath, content);
    console.log('文件处理完成并保存为', outputFilePath);
  } catch (error) {
    console.error('写入文件失败:', error.message);
  }
}

// 主函数，执行所有步骤
function processFile(inputFilePath, outputFilePath, variableMap) {
  const content = readFile(inputFilePath);
  const obfuscated = obfuscateVariables(content, variableMap);
  const withMinifiedHTML = minifyHTML(obfuscated);
  const minifiedJS = minifyJS(withMinifiedHTML);
  writeFile(outputFilePath, minifiedJS);
}

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

// 调用主函数
processFile('source.js', 'work.js', variableMap);
