本脚本实现将用户的动态IP地址映射到一个固定的域名解析服务上，本脚本以Cloudflar示例，通过配置系统计划任务，客户端程序定时通过信息传递把当前网络出口的动态IP地址传送给Cloudflare的DNS解析服务，服务器程序负责提供DNS服务并实现动态域名解析。
需要本地内网有设备并安装Python3及依赖requests

使用方法：

Linux crontab配置
$crontab -e
格式为
秒 分 时 日 月 星期 python3 ddns.py

Windows请自行探索
