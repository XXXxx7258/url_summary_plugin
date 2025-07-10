import logging
import re
import aiohttp
import asyncio
import urllib.parse
from bs4 import BeautifulSoup
from typing import List, Tuple, Optional, Set, Type
from collections import OrderedDict
import time
from src.plugin_system import (
    BasePlugin, register_plugin, BaseAction,
    ComponentInfo, ActionActivationType, ConfigField, ChatMode
)
from src.plugin_system.apis import message_api, send_api, config_api, emoji_api

logger = logging.getLogger(__name__)

# --------- 本轮激活URL去重 ---------
_recently_activated_urls: Set[str] = set()

def should_skip_url_activation(url: str) -> bool:
    """
    如果 URL 在本聊天进程中已激活过一次，则跳过后续激活。
    """
    if url in _recently_activated_urls:
        return True
    _recently_activated_urls.add(url)
    return False

try:
    from readability import Document
    readability_available = True
except ImportError:
    readability_available = False

# --------- 消息去重缓存实现（支持配置） ---------
recent_messages = OrderedDict()

def get_cache_ttl():
    try:
        plugin_inst = UrlSummaryPlugin.plugin_instance
        if plugin_inst:
            return plugin_inst.get_config("cache.cache_ttl", 600)
    except Exception:
        pass
    return 600

MAX_CACHE = 500

def is_duplicate_message(msg):
    now = time.time()
    cache_ttl = get_cache_ttl()
    if hasattr(msg, "id") and msg.id:
        key = f"id:{msg.id}"
    elif hasattr(msg, "plain_text") and msg.plain_text:
        key = f"hash:{hash(msg.plain_text)}"
    else:
        key = f"hash:{hash(str(msg))}"
    # 清理过期记录
    keys_to_del = [k for k, v in recent_messages.items() if now - v > cache_ttl]
    for k in keys_to_del:
        recent_messages.pop(k, None)
    if key in recent_messages:
        return True
    recent_messages[key] = now
    if len(recent_messages) > MAX_CACHE:
        recent_messages.popitem(last=False)
    return False

# --------- URL摘要缓存 ---------
url_summary_cache = OrderedDict()
MAX_URL_CACHE = 500

def get_url_cache_ttl():
    try:
        plugin_inst = UrlSummaryPlugin.plugin_instance
        if plugin_inst:
            return plugin_inst.get_config("cache.url_cache_ttl", 3600)
    except Exception:
        pass
    return 3600

def get_url_summary_from_cache(url):
    now = time.time()
    cache_ttl = get_url_cache_ttl()
    # 清理过期
    keys_to_del = [k for k, v in url_summary_cache.items() if now - v['time'] > cache_ttl]
    for k in keys_to_del:
        url_summary_cache.pop(k, None)
    if url in url_summary_cache:
        url_summary_cache[url]['time'] = now
        return url_summary_cache[url]['summary']
    return None

def set_url_summary_cache(url, summary):
    now = time.time()
    url_summary_cache[url] = {'summary': summary, 'time': now}
    if len(url_summary_cache) > MAX_URL_CACHE:
        url_summary_cache.popitem(last=False)

class UrlSummaryAction(BaseAction):
    """网址摘要Action - 支持关键词和LLM判断，避免重复触发"""
    action_name = "url_summary"
    action_description = "检测消息中的真实网址并发送内容摘要"
    focus_activation_type = ActionActivationType.KEYWORD
    normal_activation_type = ActionActivationType.KEYWORD
    activation_keywords = ["http://", "https://", "www.", ".com", ".cn", ".net", ".org"]
    keyword_case_sensitive = False
    mode_enable = ChatMode.ALL
    parallel_action = False

    action_parameters = {"url": "要处理的网页URL"}
    action_require = [
        "用户消息包含有效HTTP/HTTPS链接时使用",
        "链接长度大于7字符且包含域名时使用"
    ]
    llm_judge_prompt = "是否需要生成网页摘要？条件是消息包含URL且未重复。"
    associated_types = ["text"]

    DEFAULT_TIMEOUT = 10
    DEFAULT_MAX_LENGTH = 400
    MIN_URL_LENGTH = 7
    DEFAULT_MAX_SUBPAGE = 2
    DEFAULT_SUBPAGE_LENGTH = 200

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.url_validator = re.compile(
            r'^(?:(?:https?|ftp):\/\/)?'
            r'(?:\S+(?::\S*)?@)?'
            r'(?:(?:[a-zA-Z0-9\u00a1-\uffff-]{1,63}\.)+'
            r'[a-zA-Z\u00a1-\uffff]{2,})'
            r'(?::\d+)?'
            r'(?:[\/?#][^\s"]*)?'
            r'$', re.IGNORECASE
        )

    async def execute(self) -> Tuple[bool, str]:
        try:
            # 激活前检查：同轮次已处理则跳过
            urls = []
            if hasattr(self, 'action_data') and self.action_data.get("url"):
                urls = [self.normalize_url(self.action_data.get("url"))]
            elif hasattr(self, 'message') and self.message:
                urls = self.extract_and_validate_urls(self.message.plain_text)
            if urls and should_skip_url_activation(urls[0]):
                logger.info(f"URL 已在本轮激活过，跳过执行: {urls[0]}")
                return False, "该链接已处理过"

            # 消息层去重
            if hasattr(self, 'message') and is_duplicate_message(self.message):
                logger.info("检测到重复消息，跳过处理")
                return False, "已忽略重复消息"

            # 提取URL
            urls = []
            if hasattr(self, 'action_data') and self.action_data.get("url"):
                urls = [self.normalize_url(self.action_data.get("url"))]
            elif hasattr(self, 'message') and self.message:
                urls = self.extract_and_validate_urls(self.message.plain_text)
            elif hasattr(self, 'raw_message') and self.raw_message:
                urls = self.extract_and_validate_urls(self.raw_message)
            if not urls:
                return False, "未检测到有效URL"
            url = urls[0]

            # 检查摘要缓存
            cached = get_url_summary_from_cache(url)
            if cached:
                await self.send_summary(url, cached)
                return True, f"已发送 {url} 的缓存摘要"

            # 配置
            timeout = self.get_config("http.timeout", self.DEFAULT_TIMEOUT)
            max_length = self.get_config("processing.max_length", self.DEFAULT_MAX_LENGTH)
            user_agent = self.get_config("http.user_agent", "Mozilla/5.0")
            max_subpage = self.get_config("processing.max_subpage", self.DEFAULT_MAX_SUBPAGE)
            subpage_length = self.get_config("processing.subpage_length", self.DEFAULT_SUBPAGE_LENGTH)
            enable_related = self.get_config("processing.enable_related_pages", True)

            await self.send_processing_feedback()
            seen = {url}
            summary = await self.get_url_summary(
                url, timeout, max_length, user_agent,
                fetch_links=enable_related, seen_links=seen,
                max_subpage=max_subpage, subpage_length=subpage_length
            )
            if summary:
                set_url_summary_cache(url, summary)
                await self.send_summary(url, summary)
                return True, f"已发送 {url} 的内容摘要"
            return False, "无法获取网页内容"
        except asyncio.TimeoutError:
            logger.warning("请求超时")
            await self.send_timeout_message()
            return False, "请求超时"
        except Exception as e:
            logger.exception("网址摘要处理失败")
            await self.send_error_message()
            return False, f"处理失败: {str(e)}"

    async def send_processing_feedback(self):
        try:
            emoji_result = await emoji_api.get_by_emotion("processing")
            if emoji_result:
                emoji_base64, _, _ = emoji_result
                await send_api.emoji_to_user(emoji_base64, self.user_id)
        except Exception as e:
            logger.warning(f"发送处理表情失败: {str(e)}")

    async def send_summary(self, url: str, summary: str):
        display_url = url if len(url) <= 50 else f"{url[:30]}...{url[-20:]}"
        summary_msg = self.format_summary_message(display_url, summary)
        await self.send_text(summary_msg)
        try:
            emoji_result = await emoji_api.get_by_emotion("success")
            if emoji_result:
                emoji_base64, _, _ = emoji_result
                await send_api.emoji_to_user(emoji_base64, self.user_id)
        except Exception as e:
            logger.warning(f"发送成功表情失败: {str(e)}")

    def format_summary_message(self, display_url: str, summary: str) -> str:
        parts = summary.split('\n\n相关页面：', 1)
        main = parts[0].strip()
        related = parts[1].strip() if len(parts) == 2 else None
        msg = f"🔗 **网页摘要** [`{display_url}`]\n\n> {main.replace(chr(10), '\n> ')}"
        if related:
            msg += "\n\n<details><summary>相关页面</summary>\n\n"
            for sub in re.split(r"\n【(https?://[^】]+)】\n", "\n"+related):
                if not sub.strip():
                    continue
                if sub.startswith("http"):
                    continue
                msg += f"> {sub.strip().replace(chr(10), '\\n> ')}\n"
            msg += "</details>"
        return msg

    async def send_timeout_message(self):
        try:
            await self.send_text("⏱⏱⏱ 网页加载超时，请稍后再试")
            emoji_result = await emoji_api.get_by_emotion("timeout")
            if emoji_result:
                emoji_base64, _, _ = emoji_result
                await send_api.emoji_to_user(emoji_base64, self.user_id)
        except Exception as e:
            logger.warning(f"发送超时消息失败: {str(e)}")

    async def send_error_message(self):
        try:
            await self.send_text("❌❌ 处理网页内容时出错，请稍后再试")
            emoji_result = await emoji_api.get_by_emotion("error")
            if emoji_result:
                emoji_base64, _, _ = emoji_result
                await send_api.emoji_to_user(emoji_base64, self.user_id)
        except Exception as e:
            logger.warning(f"发送错误消息失败: {str(e)}")

    def extract_and_validate_urls(self, text: str) -> List[str]:
        url_pattern = r'((?:https?://)?(?:www\.)?(?:[a-zA-Z0-9\-]+\.)+[a-zA-Z]{2,}(?:/[^\s<>"]*)?)'
        potential_urls = re.findall(url_pattern, text)
        valid_urls = []
        for url in potential_urls:
            normalized_url = self.normalize_url(url)
            if self.is_valid_url(normalized_url):
                valid_urls.append(normalized_url)
        from collections import OrderedDict
        return list(OrderedDict.fromkeys(valid_urls))

    def normalize_url(self, url: str) -> str:
        url = urllib.parse.unquote(url.strip())
        if not url:
            return ""
        if not url.startswith(('http://', 'https://', 'ftp://')):
            url = "https://" + url.lstrip('/')
        return url

    def is_valid_url(self, url: str) -> bool:
        if len(url) < self.MIN_URL_LENGTH:
            return False
        if '.' not in url:
            return False
        return True

    async def get_url_summary(
        self,
        url: str,
        timeout: int,
        max_length: int,
        user_agent: str,
        fetch_links: bool = True,
        seen_links: Optional[Set[str]] = None,
        max_subpage: int = 2,
        subpage_length: int = 200
    ) -> Optional[str]:
        if not url.startswith(("http://", "https://")):
            return f"⚠️ 无效的URL格式: {url}"
        headers = {
            "User-Agent": user_agent,
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8",
            "Accept-Language": "zh-CN,zh;q=0.9"
        }
        proxy_url = self.get_config("http.proxy", "")
        if seen_links is None:
            seen_links = set()

        for attempt in range(3):
            try:
                async with aiohttp.ClientSession() as session:
                    logger.debug(f"尝试获取URL内容: {url} (尝试 {attempt+1}/3), 代理: {proxy_url}")
                    async with session.get(
                        url,
                        headers=headers,
                        timeout=aiohttp.ClientTimeout(total=timeout),
                        ssl=False,
                        proxy=proxy_url if proxy_url else None
                    ) as response:
                        if response.status != 200:
                            return f"⚠️ 无法访问网页 (状态码: {response.status})"
                        raw = await response.read()
                        encoding = response.charset
                        if not encoding:
                            try:
                                import chardet
                                encoding = chardet.detect(raw)['encoding']
                            except Exception:
                                encoding = 'utf-8'
                        try:
                            html = raw.decode(encoding or 'utf-8', errors='ignore')
                        except Exception:
                            html = raw.decode('utf-8', errors='ignore')

                        soup_for_links = BeautifulSoup(html, 'html.parser')
                        soup = BeautifulSoup(html, 'html.parser')
                        summary_mode = self.get_config("processing.summary_mode", "sentence")
                        content = self.extract_main_content(soup, html=html)
                        if summary_mode == "llm" and content:
                            summary = await self.summarize_by_llm(content, max_length)
                            meta_desc = soup.find("meta", attrs={"name": "description"}) or \
                                soup.find("meta", attrs={"property": "og:description"})
                            og_title = soup.find("meta", attrs={"property": "og:title"})
                            og_site = soup.find("meta", attrs={"property": "og:site_name"})
                            title = og_title.get("content", "").strip() if og_title else (soup.title.get_text(strip=True) if soup.title else "")
                            site = og_site.get("content", "").strip() if og_site else ""
                            desc = meta_desc.get("content", "").strip() if meta_desc else ""
                            lines = []
                            if title: lines.append(f"**{title}**")
                            if site: lines.append(f"（{site}）")
                            lines.append(summary)
                            summary = "\n".join(lines).strip()
                        else:
                            summary = self.extract_summary_from_soup(soup, html, max_length)
                        # 相关页面逻辑
                        if fetch_links:
                            internal_links = self.extract_internal_links(
                                soup_for_links, url, max_links=max_subpage, seen_links=seen_links
                            )
                            if internal_links:
                                for link in internal_links:
                                    seen_links.add(link)
                                related = await self.get_multi_url_summaries(
                                    internal_links, timeout, subpage_length, user_agent, seen_links=seen_links
                                )
                                if related:
                                    summary += "\n\n相关页面："
                                    for link, sub_summary in related:
                                        link_disp = link if len(link) <= 50 else f"{link[:30]}...{link[-20:]}"
                                        summary += f"\n【{link_disp}】\n{sub_summary}"
                        return summary
            except (aiohttp.ClientError, asyncio.TimeoutError) as e:
                logger.warning(f"请求失败 (尝试 {attempt+1}/3): {type(e).__name__}")
                if attempt == 2:
                    return f"❌❌ 请求失败: {type(e).__name__}"
                await asyncio.sleep(1)
            except Exception as e:
                logger.exception("处理错误")
                return f"❌❌ 处理错误: {type(e).__name__}"
        return "❌❌ 多次尝试后仍无法获取内容"

    async def get_multi_url_summaries(
        self, urls: list, timeout: int, max_length: int, user_agent: str, seen_links: Optional[Set[str]] = None
    ) -> list:
        results = []
        if seen_links is None:
            seen_links = set()
        for url in urls:
            if url in seen_links:
                continue
            cached_summary = get_url_summary_from_cache(url)
            if cached_summary:
                results.append((url, cached_summary))
                seen_links.add(url)
                continue
            try:
                summary = await self.get_url_summary(
                    url, timeout, max_length, user_agent, fetch_links=False, seen_links=seen_links
                )
                if summary:
                    set_url_summary_cache(url, summary)
                    results.append((url, summary))
                seen_links.add(url)
            except Exception as e:
                logger.warning(f"子页面摘要抓取失败: {url}, {str(e)}")
        return results

    def extract_internal_links(
        self, soup: BeautifulSoup, base_url: str, max_links: int = 2, seen_links: Optional[Set[str]] = None
    ) -> list:
        from urllib.parse import urljoin, urlparse
        base_domain = urlparse(base_url).netloc
        links = []
        seen = set() if seen_links is None else set(seen_links)
        for a in soup.find_all('a', href=True):
            href = a['href']
            abs_url = urljoin(base_url, href)
            link_domain = urlparse(abs_url).netloc
            if not abs_url.startswith(('http://', 'https://')):
                continue
            if (
                link_domain == base_domain
                and abs_url not in seen
                and abs_url != base_url
                and not abs_url.startswith('javascript:')
                and not abs_url.startswith('mailto:')
                and not abs_url.endswith(('.jpg', '.png', '.gif', '.svg', '.ico'))
            ):
                seen.add(abs_url)
                links.append(abs_url)
            if len(links) >= max_links:
                break
        return links

    def extract_main_content(self, soup: BeautifulSoup, html: str = None) -> str:
        if readability_available and html is not None:
            try:
                doc = Document(html)
                content = doc.summary()
                soup2 = BeautifulSoup(content, 'html.parser')
                text = soup2.get_text(" ", strip=True)
                if len(text) > 50:
                    logger.debug(f"readability正文长度: {len(text)}")
                    return text
            except Exception as e:
                logger.warning(f"readability抽取正文失败: {str(e)}")
        for tag in ['article', 'main', 'content', 'entry-content', 'body', 'section']:
            element = soup.find(tag)
            if element:
                text = element.get_text(" ", strip=True)
                logger.debug(f"标签<{tag}>正文长度: {len(text)}")
                if len(text) > 50:
                    return text
        for class_name in [
            'wp_articlecontent', 'article-content', 'articleBody', 'article', 'main', 'content', 'entry-content',
            'body', 'post', 'post-content', 'main-content', 'TRS_Editor',
            'news-content', 'content-main', 'articleText', 'contentArea'
        ]:
            element = soup.find(class_=class_name)
            if element:
                text = element.get_text(" ", strip=True)
                logger.debug(f"class={class_name} 正文长度: {len(text)}")
                if len(text) > 50:
                    return text
        paragraphs = []
        for p in soup.find_all('p'):
            text = p.get_text(" ", strip=True)
            if len(text) > 10:
                paragraphs.append(text)
        if paragraphs:
            logger.debug(f"抓到段落数: {len(paragraphs)}，合并前3段落为：{' | '.join(paragraphs[:3])}")
            return " ".join(paragraphs[:20])
        body = soup.body
        if body:
            text = body.get_text(" ", strip=True)
            logger.debug(f"<body>长度: {len(text)}")
            if len(text) > 50:
                return text
        a_tags = soup.find_all('a', href=True)
        headlines = []
        for a in a_tags:
            txt = a.get_text(strip=True)
            if txt and 5 < len(txt) < 40 and not re.search(r"[《》]", txt):
                headlines.append(txt)
            if len(headlines) >= 5:
                break
        if headlines:
            logger.debug(f"headlines fallback: {' / '.join(headlines)}")
            return " / ".join(headlines)
        logger.debug("正文提取全部失败，返回空字符串")
        return ""

    def extract_main_content_html(self, html: str) -> Optional[str]:
        if readability_available and html is not None:
            try:
                doc = Document(html)
                return doc.summary(html_partial=True)
            except Exception as e:
                logger.warning(f"readability正文html抽取失败: {str(e)}")
        return None

    def summarize_text(self, text: str, max_length: int = 400) -> str:
        import re
        text = re.sub(r'([a-zA-Z0-9])。([a-zA-Z0-9])', r'\1.\2', text)
        text = text.strip()
        if not text:
            return ""
        if len(text) <= max_length:
            return text

        summary_mode = "sentence"
        try:
            summary_mode = self.get_config("processing.summary_mode", "sentence")
        except Exception:
            pass

        if summary_mode == "llm":
            return "[LLM摘要处理中...]"

        if summary_mode == "plain":
            trunc_point = -1
            for sep in ['。', '！', '!', '？', '?', '.', '\n']:
                idx = text.rfind(sep, 0, max_length)
                if idx > trunc_point:
                    trunc_point = idx
            if trunc_point != -1 and trunc_point > max_length // 3:
                return text[:trunc_point + 1] + "..."
            return text[:max_length] + "..."

        sentences = re.split(r'([。！？!?\.])', text)
        result = ''
        total = 0
        for i in range(0, len(sentences) - 1, 2):
            seg = sentences[i] + sentences[i + 1]
            if total + len(seg) > max_length:
                break
            result += seg
            total += len(seg)
        if not result:
            return text[:max_length] + "..."
        return result.strip() + "..."

    async def summarize_by_llm(self, text, max_length: int) -> str:
        try:
            from src.plugin_system.apis import llm_api
            logger.info(f"[LLM摘要调用] prompt前100字: {text[:100]}")
            model_config_obj = llm_api.get_available_models()
            logger.info(f"models获取结果: {model_config_obj}, 类型: {type(model_config_obj)}")
            model_config_key = self.get_config("processing.llm_config_key", "utils_small")
            model_config = getattr(model_config_obj, model_config_key, None)
            if not model_config:
                logger.warning(f"未找到指定模型 {model_config_key}，尝试 fallback")
                model_config = getattr(model_config_obj, "replyer_1", None)
            if not model_config:
                logger.error("未获取到任何可用模型配置，降级本地摘要")
                return self.summarize_text(text, max_length)
            prompt = f"请将以下内容压缩为不超过{max_length}字的中文摘要：\n{text}"
            success, response, reasoning, model_used = await llm_api.generate_with_model(prompt, model_config)
            logger.info(f"[LLM摘要调用] model={model_used}, success={success}, response前100字={response[:100] if response else response}")
            if success and response:
                return response.strip()
            else:
                logger.error("[LLM摘要调用] LLM未返回结果，回退本地摘要")
                return self.summarize_text(text, max_length)
        except Exception as e:
            logger.exception(f"[LLM摘要调用] 失败: {e}")
            return self.summarize_text(text, max_length)       

    def extract_summary_from_soup(self, soup: BeautifulSoup, html: str, max_length: int) -> str:
        meta_desc = soup.find("meta", attrs={"name": "description"}) or \
            soup.find("meta", attrs={"property": "og:description"})
        og_title = soup.find("meta", attrs={"property": "og:title"})
        og_site = soup.find("meta", attrs={"property": "og:site_name"})
        title = og_title.get("content", "").strip() if og_title else (soup.title.get_text(strip=True) if soup.title else "")
        site = og_site.get("content", "").strip() if og_site else ""
        desc = meta_desc.get("content", "").strip() if meta_desc else ""
        content = self.extract_main_content(soup, html=html)
        summary_mode = "sentence"
        try:
            summary_mode = self.get_config("processing.summary_mode", "sentence")
            logger.info(f"[摘要流程] summary_mode={summary_mode}")
        except Exception:
            pass
        logger.info(f"[摘要流程] summary_mode={summary_mode}, content前50字: {content[:50]}")
        if summary_mode == "llm" and content:
            summary = "[[LLM摘要处理中]]"
        else:
            summary = desc if desc else self.summarize_text(content, max_length)
        lines = []
        if title: lines.append(f"**{title}**")
        if site: lines.append(f"（{site}）")
        lines.append(summary)
        return "\n".join(lines).strip()

@register_plugin
class UrlSummaryPlugin(BasePlugin):
    plugin_name = "url_summary_plugin"
    plugin_description = "自动检测消息中的真实网址并发送内容摘要（包括重要内链）"
    plugin_version = "2.3.3"
    plugin_author = "qingkong"
    enable_plugin = True
    config_file_name = "config.toml"
    config_section_descriptions = {
        "general": "通用设置",
        "http": "HTTP请求设置",
        "processing": "内容处理设置",
        "cache": "缓存设置"
    }
    config_schema = {
            "config_version": ConfigField(type=str, default="1.0.0", description="配置版本"),
            "general": {
                "enabled": ConfigField(type=bool, default=True, description="是否启用插件"),
                "enable_group": ConfigField(type=bool, default=True, description="是否在群聊启用"),
                "enable_private": ConfigField(type=bool, default=True, description="是否在私聊启用")
            },
            "http": {
                "timeout": ConfigField(type=int, default=10, description="请求超时时间(秒)"),
                "user_agent": ConfigField(
                    type=str,
                    default="Mozilla/5.0 (compatible; MaiBot-URL-Summary/1.0)",
                    description="HTTP请求使用的User-Agent"
                ),
                "max_retries": ConfigField(type=int, default=3, description="最大重试次数"),
                "proxy": ConfigField(type=str, default="http://127.0.0.1:7890", description="HTTP请求所用的代理地址，如 http://127.0.0.1:7890")
            },
            "processing": {
                "max_length": ConfigField(type=int, default=400, description="摘要最大长度"),
                "include_title": ConfigField(type=bool, default=True, description="是否包含标题"),
                "min_content_length": ConfigField(type=int, default=100, description="最小内容长度"),
                "max_subpage": ConfigField(type=int, default=2, description="相关页面最多抓取数量"),
                "subpage_length": ConfigField(type=int, default=200, description="相关页面摘要最大长度"),
                "enable_related_pages": ConfigField(type=bool, default=True, description="是否抓取站内相关页面摘要"),
                "summary_mode": ConfigField(
                    type=str,
                    default="sentence",
                    description="摘要生成方式，可选 llm（智能摘要）、sentence（按句截断）、plain（原样截断）"
                ),
                "llm_config_key": ConfigField(
                    type=str,
                    default="utils_small",
                    description="LLM摘要时采用的模型配置key，例如：utils_small, replyer_1, replyer_2"
                )
            },
            "cache": {
                "cache_ttl": ConfigField(type=int, default=600, description="防重复缓存时间(秒)"),
                "url_cache_ttl": ConfigField(type=int, default=3600, description="URL摘要缓存时间(秒)")
            }
        }
    plugin_instance = None

    def __init__(self, *args, **kwargs):
        UrlSummaryPlugin.plugin_instance = self
        super().__init__(*args, **kwargs)

    def get_plugin_components(self) -> List[Tuple[ComponentInfo, Type]]:
        if not self.get_config("general.enabled", True):
            return []
        components = []
        components.append((UrlSummaryAction.get_action_info(), UrlSummaryAction))
        logger.info("URL摘要插件已加载，支持消息对象: %s", hasattr(UrlSummaryAction, 'message'))
        return components
