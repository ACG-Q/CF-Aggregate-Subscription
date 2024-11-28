# Cloudflare Pages 部署指南

在本篇文章中，我们将指导您如何通过 Cloudflare Pages 部署一个名为 [CF-Aggregate-Subscription](https://github.com/ACG-Q/CF-Aggregate-Subscription) 的项目。这个过程包括 Fork 仓库、链接到 Cloudflare Pages、配置环境变量、创建和绑定 Cloudflare KV，以及重新部署项目。

## 第一步：Fork 仓库

首先，您需要在 GitHub 上 Fork [CF-Aggregate-Subscription](https://github.com/ACG-Q/CF-Aggregate-Subscription) 项目。这是为了创建一个您自己的项目副本，以便进行个性化配置和部署。

1. 访问 [CF-Aggregate-Subscription GitHub 仓库](https://github.com/ACG-Q/CF-Aggregate-Subscription)。
2. 点击页面右上角的 "Fork" 按钮，将项目复制到您的 GitHub 账户下。

## 第二步：在 Cloudflare Pages 链接仓库

接下来，您需要在 Cloudflare Pages 中链接您的 Fork 仓库。

1. 登录到您的 [Cloudflare 账户](https://dash.cloudflare.com)。
2. 在左侧菜单中选择 "Workers and Pages"。
3. 点击 "Create Application"。
4. 选择 "Connect to Git"，然后选择您的 Fork 仓库。

## 第三步：添加相关变量并部署

在您的项目中配置环境变量是部署过程中的重要一步。

1. 在 Cloudflare Pages 项目设置中找到 "Variables" 或 "Environment variables" 部分。
2. 添加以下环境变量：

| 变量名 | 示例   | 备注                 |
| ------ | ------ | -------------------- |
| PWD    | 9527   | 进入管理面板的密码   |
| SECRET | 123456 | 生成cookie的加密密钥 |

3. 保存变量并部署您的项目。

## 第四步：创建和绑定 Cloudflare KV

Cloudflare KV 是一个快速、低延迟的键值存储系统，适合用于存储配置数据。

1. 在 Cloudflare 仪表板中，找到 "Workers and Pages" 下的 "KV" 部分。
2. 点击 "Create a namespace" 并给您的 KV 命名。
3. 返回到您的 Cloudflare Pages 项目设置，在 "Bindings"  部分，添加一个新的绑定`CONFIG_KV `，并选择您刚刚创建的 KV 命名空间。

## 第五步：重新部署

完成以上步骤后，您需要重新部署您的项目以应用所有更改。

1. 在 Cloudflare Pages 的 "Deployments" 或 "Deployment" 部分，找到并点击 "Retry deployment" 或 "Deploy" 按钮。

等待部署完成，您的项目就会在 Cloudflare Pages 上运行了。您可以通过 Cloudflare 分配的子域名访问您的项目，或者如果您配置了自定义域名，也可以通过自定义域名访问。
