# CF-Aggregate-Subscription

基于 [CF-Workers-SUB](https://github.com/cmliu/CF-Workers-SUB/commit/312c109c3b967f2ed088246e2041b7e4ce1ab05e) 魔改的

## 修改项

1. 修改了数据的保存，由env改为kv
2. 修改了欢迎页面
3. 添加了管理面板、以及对应的相关登录机制

> 添加了风险，除了密码相关的东西，其余的都暴露在外, 即 你的订阅信息、你的token 等等
> 不过我只是学习使用，所以无所谓呐(~有时间再说吧~)

## 必要变量

| 变量名 | 示例 | 备注 | 
|--------|---------|-----|
| PWD | 9527  | 进入管理面板的密码 | 
| SECRET | 123456 | 生成cookie的加密密钥 |
| CONFIG_KV | `kv` | 自己在KV里面任意创建一个即可 |

## 部署

> 自行参考[Cloudflare Pages 部署指南](deployment/page.md)、以及其他的部署到Cloudflare Pages的教程

## 使用方法

> 自行参考[CF-Workers-SUB](https://github.com/cmliu/CF-Workers-SUB)

## 配置面板

部分参数，我在CF-Workers-SUB没有找到相关描述，所以是由AI帮忙生成的