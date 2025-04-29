import requests
import time
import sys
from typing import Optional, Dict, Any, List, Tuple


# 状态码定义
class StatusCode:
    SUCCESS = 0
    IP_FETCH_ERROR = 2
    API_ERROR = 3
    RECORD_NOT_FOUND = 4
    UPDATE_ERROR = 5
    CREATE_ERROR = 6
    UNKNOWN_ERROR = 99


class Config:
    # Cloudflare配置参数 - 实际使用时请修改这些值
    DNS_NAME = ''  # 自有域名
    ZONE_ID = ''   # Cloudflare对应域名的区域ID，位置在域名概述界面右下
    API_TOKEN = ''  # Cloudflare用户API令牌，获取API令牌https://dash.cloudflare.com/profile/api-tokens
    PROXIED = False
    MAX_RETRIES = 3
    RETRY_DELAY = 5

    # 企业微信通知配置，使用时需自行搜索配置企业应用
    CORP_ID = ''  # 每个企业都拥有唯一的corpid,获取此信息可在管理后台"我的企业" - "企业信息"下查看"企业ID"(需要有管理员权限)
    CORP_SECRET = ''  # 企业应用里面用于报障数据安全的"钥匙"，每个应用都有一个独立的访问密钥，为了保证数据的安全，secret不能泄露
    AGENT_ID =   # 每个应用都有唯一的agentid。在管理后台->"应用与小程序"->"应用"，点进某个应用，即可以看到agentid
    USER_ID = ''  # 接收消息的用户ID


class WechatNotifier:
    def __init__(self, corp_id: str, corp_secret: str, agent_id: int, user_id: str):
        self.corp_id = corp_id
        self.corp_secret = corp_secret
        self.agent_id = agent_id
        self.user_id = user_id
        self.access_token = None
        self.token_expires = 0

    def get_access_token(self) -> str:
        """获取企业微信接口访问令牌"""
        current_time = time.time()

        # 如果token未过期，直接返回现有token
        if self.access_token and self.token_expires > current_time:
            return self.access_token

        # 获取新token
        try:
            url = f"https://qyapi.weixin.qq.com/cgi-bin/gettoken?corpid={self.corp_id}&corpsecret={self.corp_secret}"
            response = requests.get(url, timeout=10)
            data = response.json()

            if data.get('errcode') == 0:
                self.access_token = data.get('access_token')
                self.token_expires = current_time + data.get('expires_in', 7200) - 200  # 提前200秒过期
                return self.access_token
            else:
                print(f"获取企业微信token失败: {data.get('errmsg', '未知错误')}")
                return None
        except Exception as e:
            print(f"获取企业微信token异常: {str(e)}")
            return None

    def send_notification(self, message: str) -> bool:
        """发送企业微信通知"""
        if len(message.strip()) <= 11:  # 与原脚本保持一致，不发送过短的消息
            return False

        token = self.get_access_token()
        if not token:
            return False

        try:
            url = f"https://qyapi.weixin.qq.com/cgi-bin/message/send?access_token={token}"

            payload = {
                "touser": self.user_id,
                "msgtype": "text",
                "agentid": self.agent_id,
                "text": {
                    "content": message
                },
                "safe": 0
            }

            response = requests.post(url, json=payload, timeout=10)
            data = response.json()

            if data.get('errcode') == 0:
                return True
            else:
                print(f"发送企业微信通知失败: {data.get('errmsg', '未知错误')}")
                return False
        except Exception as e:
            print(f"发送企业微信通知异常: {str(e)}")
            return False


class CloudflareDDNS:
    def __init__(self, dns_name: str, zone_id: str, token: str, proxied: bool = False,
                 max_retries: int = 3, retry_delay: int = 5, notifier: WechatNotifier = None):
        self.dns_name = dns_name
        self.zone_id = zone_id
        self.token = token
        self.proxied = proxied
        self.max_retries = max_retries
        self.retry_delay = retry_delay
        self.headers = {
            'Authorization': f'Bearer {token}',
            'Content-Type': 'application/json'
        }
        self.status_message = ""
        self.status_code = StatusCode.UNKNOWN_ERROR
        self.notifier = notifier

    def get_public_ip(self) -> Optional[str]:
        """获取公网IPv4地址"""
        ip_services = [
            'https://ipv4.ident.me',
            'https://api.ipify.org',
            'https://v4.ident.me'
        ]

        for service in ip_services:
            try:
                response = requests.get(service, timeout=10)
                if response.status_code == 200:
                    ip = response.text.strip()
                    if self._validate_ipv4(ip):
                        return ip
            except Exception:
                continue

        self.status_message = "无法获取有效的IPv4地址"
        self.status_code = StatusCode.IP_FETCH_ERROR
        return None

    def _validate_ipv4(self, ip: str) -> bool:
        """验证IPv4地址格式"""
        parts = ip.split('.')
        if len(parts) != 4:
            return False

        try:
            return all(0 <= int(p) <= 255 for p in parts)
        except ValueError:
            return False

    def _make_api_request(self, method: str, url: str, json_data: Dict = None) -> Optional[Dict]:
        """统一处理API请求"""
        for attempt in range(self.max_retries):
            try:
                if method.upper() == 'GET':
                    response = requests.get(url, headers=self.headers, timeout=10)
                elif method.upper() == 'PUT':
                    response = requests.put(url, headers=self.headers, json=json_data, timeout=10)
                elif method.upper() == 'POST':
                    response = requests.post(url, headers=self.headers, json=json_data, timeout=10)
                else:
                    self.status_message = f"不支持的HTTP方法: {method}"
                    return None

                data = response.json()
                if data.get('success'):
                    return data
                else:
                    error_msg = data.get('errors', [{}])[0].get('message', '未知错误')
                    self.status_message = f"API请求失败: {error_msg}"
                    self.status_code = StatusCode.API_ERROR
            except requests.RequestException as e:
                self.status_message = f"API请求异常: {str(e)}"
                self.status_code = StatusCode.API_ERROR

            if attempt < self.max_retries - 1:
                time.sleep(self.retry_delay)

        return None

    def get_dns_records(self) -> Optional[List[Dict[str, Any]]]:
        """获取所有DNS记录"""
        url = f'https://api.cloudflare.com/client/v4/zones/{self.zone_id}/dns_records'
        data = self._make_api_request('GET', url)

        if data:
            return data.get('result', [])
        return None

    def get_record_info(self) -> Tuple[Optional[str], Optional[str]]:
        """获取A记录的ID和当前IP"""
        records = self.get_dns_records()
        if not records:
            self.status_message = "无法获取DNS记录列表"
            self.status_code = StatusCode.API_ERROR
            return None, None

        for record in records:
            if record.get('name') == self.dns_name and record.get('type') == 'A':
                return record.get('id'), record.get('content')

        self.status_message = f"未找到域名 {self.dns_name} 的A记录"
        self.status_code = StatusCode.RECORD_NOT_FOUND
        return None, None

    def update_dns_record(self, dns_id: str, ip: str) -> bool:
        """更新DNS记录"""
        url = f'https://api.cloudflare.com/client/v4/zones/{self.zone_id}/dns_records/{dns_id}'
        payload = {
            'type': 'A',
            'name': self.dns_name,
            'content': ip,
            'proxied': self.proxied
        }

        data = self._make_api_request('PUT', url, payload)
        if data:
            self.status_message = f"成功更新A记录: {ip}"
            self.status_code = StatusCode.SUCCESS
            return True

        self.status_code = StatusCode.UPDATE_ERROR
        return False

    def create_dns_record(self, ip: str) -> bool:
        """创建新的DNS记录"""
        url = f'https://api.cloudflare.com/client/v4/zones/{self.zone_id}/dns_records'
        payload = {
            'type': 'A',
            'name': self.dns_name,
            'content': ip,
            'ttl': 1,  # 自动TTL
            'proxied': self.proxied
        }

        data = self._make_api_request('POST', url, payload)
        if data:
            self.status_message = f"成功创建A记录: {ip}"
            self.status_code = StatusCode.SUCCESS
            return True

        self.status_code = StatusCode.CREATE_ERROR
        return False

    def notify(self, message: str) -> None:
        """发送通知"""
        if self.notifier:
            self.notifier.send_notification(message)

    def update(self) -> int:
        """更新DNS记录"""
        try:
            # 获取当前公网IP
            current_ip = self.get_public_ip()
            if not current_ip:
                error_msg = f"错误: {self.status_message}"
                self.notify(f"[Cloudflare DDNS] {error_msg}")
                return self.status_code

            # 获取DNS记录ID和当前记录的IP
            record_id, record_ip = self.get_record_info()

            if record_id and record_ip:
                if current_ip != record_ip:
                    if self.update_dns_record(record_id, current_ip):
                        success_msg = f"更新成功! 当前IP: {current_ip}"
                        self.notify(f"[Cloudflare DDNS] {success_msg}")
                    else:
                        error_msg = f"更新失败: {self.status_message}"
                        self.notify(f"[Cloudflare DDNS] {error_msg}")
                # IP地址未变更时不发送任何通知
            elif not record_id:
                if self.create_dns_record(current_ip):
                    success_msg = f"创建记录成功! 当前IP: {current_ip}"
                    self.notify(f"[Cloudflare DDNS] {success_msg}")
                else:
                    error_msg = f"创建记录失败: {self.status_message}"
                    self.notify(f"[Cloudflare DDNS] {error_msg}")

        except Exception as e:
            error_msg = f"更新过程中发生异常: {str(e)}"
            self.status_message = error_msg
            self.status_code = StatusCode.UNKNOWN_ERROR
            self.notify(f"[Cloudflare DDNS] 错误: {self.status_message}")

        return self.status_code


def main():
    try:
        # 创建企业微信通知器
        notifier = WechatNotifier(
            corp_id=Config.CORP_ID,
            corp_secret=Config.CORP_SECRET,
            agent_id=Config.AGENT_ID,
            user_id=Config.USER_ID
        )

        # 创建DDNS对象
        ddns = CloudflareDDNS(
            dns_name=Config.DNS_NAME,
            zone_id=Config.ZONE_ID,
            token=Config.API_TOKEN,
            proxied=Config.PROXIED,
            max_retries=Config.MAX_RETRIES,
            retry_delay=Config.RETRY_DELAY,
            notifier=notifier
        )

        # 执行更新
        status_code = ddns.update()
        return status_code
    except Exception as e:
        error_msg = f"程序执行出错: {str(e)}"

        # 发送关键错误通知
        try:
            notifier = WechatNotifier(
                corp_id=Config.CORP_ID,
                corp_secret=Config.CORP_SECRET,
                agent_id=Config.AGENT_ID,
                user_id=Config.USER_ID
            )
            notifier.send_notification(f"[Cloudflare DDNS] 程序执行出错: {str(e)}")
        except:
            pass

        return StatusCode.UNKNOWN_ERROR


if __name__ == "__main__":
    sys.exit(main())
