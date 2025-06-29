# 网址摘要插件

## 功能介绍

- 能自动识别各种常见的网址格式（如 http、https、www、.com、.cn 等）
- 自动提取网页正文、meta描述、新闻段落，生成简明摘要
- 会顺带抓取本网站内的相关页面（如新闻详情、栏目页），并自动摘要
- 内置防重复机制，10分钟内同样的内容不会重复刷屏
- 兼容大多数新闻、门户、学校官网、博客等页面

---

## 依赖说明

安装插件前请确保 Python 环境已安装以下依赖：

- `aiohttp`：异步请求网页内容
- `beautifulsoup4`：解析网页结构
- `readability-lxml`（可选）：更智能地提取正文
- `chardet`：自动检测网页编码

安装依赖命令（任选其一）：

```bash
pip install aiohttp beautifulsoup4 readability-lxml chardet
# 或
pip install -r requirements.txt
```

---

## 使用方法

1. 把 `plugin.py` 文件放到你的插件目录下。
2. 如需自定义参数，可修改 `config.toml` 配置文件（见下文）。
3. 插件默认启动，无需手动加载。

---

## 配置说明

`config.toml` 示例与参数注释如下：

```toml
[general]
enabled = true                # 插件开关
enable_group = true           # 群聊开关
enable_private = true         # 私聊开关

[http]
timeout = 10                  # 请求超时时间（秒）
user_agent = "Mozilla/5.0 (compatible; MaiBot-URL-Summary/1.0)"
max_retries = 3               # 最大重试次数

[processing]
max_length = 400              # 摘要最大长度
include_title = true          # 是否包含标题
min_content_length = 100      # 最小内容长度
max_subpage = 2               # 相关页面最多抓几个
subpage_length = 200          # 相关页面摘要最大字数
enable_related_pages = true   # 是否抓取站内相关页面

[cache]
cache_ttl = 600               # 防重复缓存时间（秒），默认10分钟
```

---

## 工作机制说明

- 收到消息后，插件会先查防重复缓存，10分钟内同内容不会重复回复。
- 抓取内容时，优先获取 meta、og 描述；若没有则抓正文段落；若仍无内容则列出页面标题。
- 相关页面最多抓取 2 个站内链接，自动跳过无内容、重复或无意义页面。
- 修正了全角句号、防乱码和网址特殊符号问题。
![插件项目目录结构截图](screenshot.png)