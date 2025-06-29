import logging
import re
import aiohttp
import asyncio
import urllib.parse
from bs4 import BeautifulSoup
from typing import List, Tuple, Type, Optional, Set
from collections import OrderedDict
import time
from src.plugin_system import (
    BasePlugin, register_plugin, BaseAction,
    ComponentInfo, ActionActivationType, ConfigField, ChatMode
)
from src.plugin_system.apis import message_api, send_api, config_api, emoji_api

logger = logging.getLogger(__name__)

try:
    from readability import Document
    readability_available = True
except ImportError:
    readability_available = False

# --------- 去重缓存实现（支持配置） ---------
recent_messages = OrderedDict()

def get_cache_ttl():
    # 动态读取缓存时间（秒），无配置则用600
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
    key = None
    # 优先用消息ID，如无则用内容hash
    if hasattr(msg, "id") and msg.id:
        key = f"id:{msg.id}"
    elif hasattr(msg, "plain_text") and msg.plain_text:
        key = f"hash:{hash(msg.plain_text)}"
    else:
        key = f"hash:{hash(str(msg))}"
    # 清理过期
    keys_to_del = [k for k, v in recent_messages.items() if now - v > cache_ttl]
    for k in keys_to_del:
        recent_messages.pop(k, None)
    if key in recent_messages:
        return True
    recent_messages[key] = now
    if len(recent_messages) > MAX_CACHE:
        recent_messages.popitem(last=False)
    return False

class UrlSummaryAction(BaseAction):
    """网址摘要Action - 智能检测并总结网页内容，并对主站内重要链接做二级摘要"""
    # === 激活控制 ===
    action_name = "url_summary"
    action_description = "检测消息中的真实网址并发送内容摘要"
    focus_activation_type = ActionActivationType.KEYWORD
    normal_activation_type = ActionActivationType.KEYWORD
    activation_keywords = ["http://", "https://", "www.", ".com", ".cn", ".net", ".org"]
    keyword_case_sensitive = False
    mode_enable = ChatMode.ALL
    parallel_action = False

    # === 功能定义 ===
    action_parameters = {"url": "要处理的网页URL"}
    action_require = [
        "当消息包含真实有效的网址时使用",
        "需要提取网页主要内容时使用",
        "用户分享真实链接时提供摘要"
    ]
    associated_types = ["text"]

    # 配置默认值
    DEFAULT_TIMEOUT = 10
    DEFAULT_MAX_LENGTH = 400  # 建议400字符，约200汉字
    MIN_URL_LENGTH = 7  # 更宽松：原来是10，放宽为7
    DEFAULT_MAX_SUBPAGE = 2      # 最多抓取2个内链摘要
    DEFAULT_SUBPAGE_LENGTH = 200 # 子页面摘要最大长度

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        # 更宽松的正则：允许没有协议，仅需包含点和两段
        self.url_validator = re.compile(
            r'^(?:(?:https?|ftp):\/\/)?'
            r'(?:\S+(?::\S*)?@)?'
            r'(?:(?:[a-zA-Z0-9\u00a1-\uffff-]{1,63}\.)+'
            r'[a-zA-Z\u00a1-\uffff]{2,})'
            r'(?::\d+)?'
            r'(?:[/?#][^\s"]*)?'
            r'$', re.IGNORECASE
        )

    async def execute(self) -> Tuple[bool, str]:
        # --------- 去重判断 ---------
        if hasattr(self, 'message'):
            if is_duplicate_message(self.message):
                logger.info("检测到重复消息，跳过处理")
                return False, "已忽略重复消息"
        # --------- 业务逻辑 ---------
        try:
            logger.debug(f"UrlSummaryAction 收到 action_data: {getattr(self, 'action_data', {})}")
            logger.debug(f"消息对象存在: {hasattr(self, 'message')}")
            urls = []
            if hasattr(self, 'action_data') and self.action_data:
                url_param = self.action_data.get("url", "")
                logger.debug(f"规划器提供的URL参数: {url_param}")
                if url_param and self.is_valid_url(url_param):
                    urls = [self.normalize_url(url_param)]
                else:
                    urls = self.extract_and_validate_urls(url_param)
            if not urls and hasattr(self, 'message') and self.message:
                logger.debug("尝试从消息对象中提取URL")
                message_text = self.message.plain_text
                urls = self.extract_and_validate_urls(message_text)
            if not urls and hasattr(self, 'raw_message') and self.raw_message:
                logger.debug("尝试从原始消息文本中提取URL")
                urls = self.extract_and_validate_urls(self.raw_message)
            if not urls:
                logger.debug("未检测到有效URL，跳过处理")
                return False, "未检测到有效URL"
            url = urls[0]
            logger.info(f"开始处理URL: {url}")

            timeout = self.get_config("http.timeout", self.DEFAULT_TIMEOUT)
            max_length = self.get_config("processing.max_length", self.DEFAULT_MAX_LENGTH)
            user_agent = self.get_config(
                "http.user_agent",
                "Mozilla/5.0 (compatible; MaiBot-URL-Summary/1.0)"
            )
            max_subpage = self.get_config("processing.max_subpage", self.DEFAULT_MAX_SUBPAGE)
            subpage_length = self.get_config("processing.subpage_length", self.DEFAULT_SUBPAGE_LENGTH)
            enable_related_pages = self.get_config("processing.enable_related_pages", True)

            await self.send_processing_feedback()
            seen_links = set([url])
            summary = await self.get_url_summary(
                url, timeout, max_length, user_agent,
                fetch_links=enable_related_pages,
                seen_links=seen_links,
                max_subpage=max_subpage,
                subpage_length=subpage_length,
            )
            if summary:
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
        summary_msg = f"🔗🔗 网页摘要 [{display_url}]:\n{summary}"
        await self.send_text(summary_msg)
        try:
            emoji_result = await emoji_api.get_by_emotion("success")
            if emoji_result:
                emoji_base64, _, _ = emoji_result
                await send_api.emoji_to_user(emoji_base64, self.user_id)
        except Exception as e:
            logger.warning(f"发送成功表情失败: {str(e)}")

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
        return valid_urls

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
        headers = {"User-Agent": user_agent}
        if seen_links is None:
            seen_links = set()
        for attempt in range(3):
            try:
                async with aiohttp.ClientSession() as session:
                    logger.debug(f"尝试获取URL内容: {url} (尝试 {attempt+1}/3)")
                    async with session.get(
                        url,
                        headers=headers,
                        timeout=aiohttp.ClientTimeout(total=timeout),
                        ssl=False
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
                        summary = self.extract_summary_from_soup(soup, html, max_length)
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
            try:
                summary = await self.get_url_summary(
                    url, timeout, max_length, user_agent, fetch_links=False, seen_links=seen_links
                )
                if summary:
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
                and not abs_url.endswith('.jpg')
                and not abs_url.endswith('.png')
                and not abs_url.endswith('.gif')
                and not abs_url.endswith('.svg')
                and not abs_url.endswith('.ico')
            ):
                seen.add(abs_url)
                links.append(abs_url)
            if len(links) >= max_links:
                break
        return links

    def extract_summary_from_soup(self, soup: BeautifulSoup, html: str, max_length: int) -> str:
        meta_desc = soup.find("meta", attrs={"name": "description"}) or \
            soup.find("meta", attrs={"property": "og:description"})
        og_title = soup.find("meta", attrs={"property": "og:title"})
        og_site = soup.find("meta", attrs={"property": "og:site_name"})
        title = og_title.get("content", "").strip() if og_title else (soup.title.get_text(strip=True) if soup.title else "")
        site = og_site.get("content", "").strip() if og_site else ""
        desc = meta_desc.get("content", "").strip() if meta_desc else ""
        content = self.extract_main_content(soup, html=html)
        summary = desc if desc else self.summarize_text(content, max_length)
        lines = []
        if title: lines.append(f"[{title}]")
        if site: lines.append(f"（{site}）")
        lines.append(summary)
        return "\n".join(lines).strip()

    def extract_main_content(self, soup: BeautifulSoup, html: str = None) -> str:
        if readability_available and html is not None:
            try:
                doc = Document(html)
                content = doc.summary()
                soup2 = BeautifulSoup(content, 'html.parser')
                text = soup2.get_text(" ", strip=True)
                if len(text) > 50:
                    return text
            except Exception as e:
                logger.warning(f"readability抽取正文失败: {str(e)}")
        for tag in ['article', 'main', 'content', 'entry-content']:
            element = soup.find(tag)
            if element:
                return element.get_text(" ", strip=True)
        for class_name in ['content', 'article', 'post-content', 'main-content', 'body']:
            element = soup.find(class_=class_name)
            if element:
                return element.get_text(" ", strip=True)
        paragraphs = []
        for p in soup.find_all('p'):
            text = p.get_text(" ", strip=True)
            if 30 < len(text) < 1500:
                paragraphs.append(text)
        if not paragraphs:
            a_tags = soup.find_all('a', href=True)
            headlines = []
            for a in a_tags:
                txt = a.get_text(strip=True)
                if txt and 5 < len(txt) < 40 and not re.search(r"[《》]", txt):
                    headlines.append(txt)
                if len(headlines) >= 5:
                    break
            if headlines:
                return " / ".join(headlines)
        return " ".join(paragraphs[:15])

    def extract_main_content_html(self, html: str) -> Optional[str]:
        if readability_available and html is not None:
            try:
                doc = Document(html)
                return doc.summary(html_partial=True)
            except Exception as e:
                logger.warning(f"readability正文html抽取失败: {str(e)}")
        return None

    def summarize_text(self, text: str, max_length: int=400) -> str:
        import re
        text = re.sub(r'([a-zA-Z0-9])。([a-zA-Z0-9])', r'\1.\2', text)
        sentences = re.split(r'([。.!！?\n])', text)
        summary = ""
        for i in range(0, len(sentences), 2):
            s = sentences[i].strip()
            if not s:
                continue
            end = sentences[i+1] if i+1 < len(sentences) else ""
            if re.match(r'^https?://', s) or re.match(r'^www\.', s) or ('.' in s and ' ' not in s and not re.search(r'[\u4e00-\u9fa5]', s)):
                summary += s
            else:
                summary += s + (end if end else "。")
            if len(summary) > max_length:
                summary = summary[:max_length]
                break
        return summary[:max_length] + ("..." if len(summary) > max_length else "")

    def truncate_text(self, text: str, max_length: int) -> str:
        if len(text) <= max_length:
            return text
        trunc_point = max_length
        for i in range(max_length, max(0, max_length-100), -1):
            if text[i] in ('.', '。', '!', '！', '?', '？', '\n'):
                trunc_point = i + 1
                break
        return text[:trunc_point] + "..."

@register_plugin
class UrlSummaryPlugin(BasePlugin):
    plugin_name = "url_summary_plugin"
    plugin_description = "自动检测消息中的真实网址并发送内容摘要（包括重要内链）"
    plugin_version = "2.3.3"
    plugin_author = "Your Name"
    enable_plugin = True
    config_file_name = "config.toml"
    config_section_descriptions = {
        "general": "通用设置",
        "http": "HTTP请求设置",
        "processing": "内容处理设置",
        "cache": "缓存设置"
    }
    config_schema = {
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
            "max_retries": ConfigField(type=int, default=3, description="最大重试次数")
        },
        "processing": {
            "max_length": ConfigField(type=int, default=400, description="摘要最大长度"),
            "include_title": ConfigField(type=bool, default=True, description="是否包含标题"),
            "min_content_length": ConfigField(type=int, default=100, description="最小内容长度"),
            "max_subpage": ConfigField(type=int, default=2, description="相关页面最多抓取数量"),
            "subpage_length": ConfigField(type=int, default=200, description="相关页面摘要最大长度"),
            "enable_related_pages": ConfigField(type=bool, default=True, description="是否抓取站内相关页面摘要")
        },
        "cache": {
            "cache_ttl": ConfigField(type=int, default=600, description="防重复缓存时间(秒)")
        }
    }

    plugin_instance = None  # for global config reading

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