from DrissionPage import ChromiumOptions, Chromium
import time
import logging
from faker import Faker
import random
import string
import os
import requests
import hashlib
import json
import re
import imaplib
import email
from email.header import decode_header
from dotenv import load_dotenv
import csv
from datetime import datetime

class DeepSiderMailHandler:
    def __init__(self):
        # 加载环境变量
        load_dotenv()
        
        # 邮箱配置
        self.domain = os.getenv("DOMAIN", "").strip()  # 域名配置(用于生成注册邮箱)
        self.temp_mail = os.getenv("TEMP_MAIL", "").strip()  # 邮箱前缀
        self.temp_mail_epin = os.getenv("TEMP_MAIL_EPIN", "").strip()
        self.temp_mail_ext = os.getenv("TEMP_MAIL_EXT", "").strip()  # tempmail.plus的后缀
        self.session = requests.Session()
        
    def generate_email(self):
        """生成随机域名邮箱(用于注册)"""
        random_str = ''.join(random.choices(string.ascii_lowercase + string.digits, k=8))
        email = f"{self.temp_mail}_{random_str}@{self.domain}"
        return email
        
    def get_verification_code(self, max_retries=5, retry_interval=10):
        """获取验证码"""
        for attempt in range(max_retries):
            try:
                code = self._get_code_by_tempmail()
                
                if code:
                    return code
                    
                if attempt < max_retries - 1:
                    logging.info(f"未找到验证码,等待 {retry_interval} 秒后重试...")
                    time.sleep(retry_interval)
                    
            except Exception as e:
                logging.error(f"获取验证码失败: {str(e)}")
                if attempt < max_retries - 1:
                    time.sleep(retry_interval)
                    
        return None
        
    def _get_code_by_imap(self):
        """通过IMAP获取验证码"""
        try:
            mail = imaplib.IMAP4_SSL(self.imap_server, self.imap_port)
            mail.login(self.imap_user, self.imap_pass)
            mail.select(self.imap_dir)
            
            # 搜索最新的邮件
            _, messages = mail.search(None, 'FROM', '"no-reply@chargpt.ai"')
            if not messages[0]:
                return None
                
            latest_email_id = messages[0].split()[-1]
            _, msg_data = mail.fetch(latest_email_id, '(RFC822)')
            email_body = msg_data[0][1]
            
            # 解析邮件
            email_message = email.message_from_bytes(email_body)
            
            # 获取邮件内容
            if email_message.is_multipart():
                for part in email_message.walk():
                    if part.get_content_type() == "text/plain":
                        body = part.get_payload(decode=True).decode()
                        break
            else:
                body = email_message.get_payload(decode=True).decode()
                
            # 提取验证码 - 6位数字
            code_pattern = r'\b\d{6}\b'
            matches = re.findall(code_pattern, body)
            
            if matches:
                return matches[0]
                
        except Exception as e:
            logging.error(f"IMAP获取验证码失败: {str(e)}")
            
        finally:
            try:
                mail.close()
                mail.logout()
            except:
                pass
                
        return None
        
    def _get_code_by_tempmail(self):
        """通过tempmail.plus获取验证码"""
        try:
            mail_list_url = "https://tempmail.plus/api/mails"
            params = {
                "email": f"{self.temp_mail}{self.temp_mail_ext}",
                "limit": 20,  # 获取最近20封邮件
                "epin": self.temp_mail_epin
            }
            
            response = self.session.get(mail_list_url, params=params)
            data = response.json()
            
            if not data.get("result"):
                return None
                
            # 获取所有邮件ID并按时间排序
            mails = data.get("mail_list", [])
            if not mails:
                return None
                
            # 获取最新的邮件ID
            latest_mail = mails[0]  # mail_list已按时间倒序排列
            latest_id = latest_mail.get("mail_id")
            
            if not latest_id:
                return None
                
            # 获取最新邮件内容
            mail_detail_url = f"https://tempmail.plus/api/mails/{latest_id}"
            response = self.session.get(mail_detail_url, params={
                "email": f"{self.temp_mail}{self.temp_mail_ext}",
                "epin": self.temp_mail_epin
            })
            
            mail_data = response.json()
            if not mail_data.get("result"):
                return None
                
            # 提取验证码
            mail_text = mail_data.get("text", "")
            code_pattern = r'\b\d{6}\b'
            matches = re.findall(code_pattern, mail_text)
            
            if matches:
                logging.info(f"获取到最新验证码: {matches[0]}")
                return matches[0]
                
        except Exception as e:
            logging.error(f"Tempmail获取验证码失败: {str(e)}")
            
        return None

class DeepSiderRegistration:
    def __init__(self):
        self.fake = Faker()
        self.base_url = "https://api.chargpt.ai/api"
        self.invite_code = "67e0bb036616194f857083df"
        self.session = requests.Session()
        self.mail_handler = DeepSiderMailHandler()
        
        # 设置请求头
        self.headers = {
            'Content-Type': 'application/json',
            'Accept': 'application/json',
            'Origin': 'chrome-extension://minfmdkpoboejckenbchpjbjjkbdebdm',
            'i-lang': 'zh-CN',
            'i-version': '1.0.7',
            'i-sign': ''
        }
        
    def encrypt_password(self, password):
        """MD5加密密码"""
        return hashlib.md5(password.encode()).hexdigest()
        
    def generate_account(self):
        """生成随机账号信息"""
        email = f"ds_{self.fake.user_name()}@{self.fake.free_email_domain()}"
        password = ''.join(random.choices(string.ascii_letters + string.digits + "!@#$%^&*", k=12))
        return email, password
        
    def check_email(self, email):
        """检查邮箱是否可用"""
        url = f"{self.base_url}/verify/check-email"
        data = {"email": email}
        
        response = self.session.post(url, json=data, headers=self.headers)
        return response.status_code == 200
        
    def send_email_code(self, email):
        """发送验证码"""
        url = f"{self.base_url}/verify/send-email"
        data = {
            "email": email,
            "type": "register"
        }
        
        response = self.session.post(url, json=data, headers=self.headers)
        return response.status_code == 200
        
    def register_account(self, email, password, email_code):
        """注册账号"""
        url = f"{self.base_url}/user/register"
        
        # 加密密码
        encrypted_password = self.encrypt_password(password)
        
        # 构造完整的注册数据
        data = {
            "email": email,
            "password": encrypted_password,
            "emailCode": email_code,
            "invitationId": self.invite_code,
            "gtag": {
                "utm_source": "unknow",
                "utm_medium": "unknow", 
                "utm_campaign": "unknow",
                "utm_term": "unknow",
                "utm_content": "unknow",
                "utm_id": "unknow"
            },
            "referer": ""
        }
        
        response = self.session.post(url, json=data, headers=self.headers)
        return response.status_code == 200, response.json()
        
    def register(self):
        """执行完整注册流程"""
        try:
            # 生成随机邮箱
            email = self.mail_handler.generate_email()
            password = ''.join(random.choices(string.ascii_letters + string.digits + "!@#$%^&*", k=12))
            logging.info(f"使用邮箱: {email}")
            
            # 保存当前邮箱到mail_handler
            self.mail_handler.current_email = email
            
            # 检查邮箱
            logging.info("检查邮箱...")
            if not self.check_email(email):
                logging.error("邮箱检查失败")
                return None
                
            # 发送验证码
            logging.info("发送验证码...")
            if not self.send_email_code(email):
                logging.error("验证码发送失败")
                return None
                
            # 等待验证码邮件到达
            logging.info("等待验证码邮件到达...")
            time.sleep(10)  # 等待10秒
            
            # 自动获取验证码
            email_code = self.mail_handler.get_verification_code()
            if not email_code:
                logging.error("获取验证码失败")
                return None
            
            # 注册账号
            logging.info("提交注册...")
            success, response = self.register_account(email, password, email_code)
            
            if success:
                logging.info("注册成功!")
                return {
                    "email": email,
                    "password": password,
                    "status": "success"
                }
            else:
                logging.error(f"注册失败: {response}")
                return None
                
        except Exception as e:
            logging.error(f"注册过程出错: {str(e)}")
            return None

def batch_register(total_accounts=30, wait_between=60):
    """
    批量注册账号
    
    Args:
        total_accounts: 需要注册的账号总数
        wait_between: 每次注册之间的等待时间(秒)
    
    Returns:
        成功注册的账号列表
    """
    # 创建结果文件名
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    result_file = f"deepsider_accounts_{timestamp}.csv"
    
    # 创建注册器
    registration = DeepSiderRegistration()
    successful_accounts = []
    
    # CSV 文件头
    with open(result_file, 'w', newline='', encoding='utf-8') as f:
        writer = csv.writer(f)
        writer.writerow(['Email', 'Password', 'Registration Time'])
    
    # 开始批量注册
    for i in range(1, total_accounts + 1):
        logging.info(f"=== 开始第 {i}/{total_accounts} 个账号注册 ===")
        
        # 注册一个账号
        result = registration.register()
        
        if result:
            # 注册成功，保存账号信息
            successful_accounts.append(result)
            
            # 同时写入CSV文件
            with open(result_file, 'a', newline='', encoding='utf-8') as f:
                writer = csv.writer(f)
                writer.writerow([
                    result['email'], 
                    result['password'], 
                    datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                ])
            
            logging.info(f"第 {i} 个账号注册成功，已保存到 {result_file}")
        else:
            logging.error(f"第 {i} 个账号注册失败")
        
        # 打印当前进度
        logging.info(f"已完成: {i}/{total_accounts}, 成功: {len(successful_accounts)}")
        
        # 如果不是最后一个，等待一段时间再继续
        if i < total_accounts:
            logging.info(f"等待 {wait_between} 秒后继续...")
            time.sleep(wait_between)
    
    # 打印最终结果统计
    logging.info(f"===== 批量注册完成 =====")
    logging.info(f"总注册尝试: {total_accounts}")
    logging.info(f"成功注册数: {len(successful_accounts)}")
    logging.info(f"账号已保存到: {result_file}")
    
    # 同时在控制台打印所有账号信息
    print("\n===== 所有成功注册的账号 =====")
    for account in successful_accounts:
        print(f"邮箱: {account['email']}, 密码: {account['password']}")
    
    return successful_accounts

if __name__ == "__main__":
    # 设置日志
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(levelname)s - %(message)s',
        handlers=[
            logging.FileHandler("deepsider_registration.log"),
            logging.StreamHandler()
        ]
    )
    
    # 执行批量注册 (30个账号，每次注册间隔60秒)
    accounts = batch_register(total_accounts=30, wait_between=10)
    
    # 最终结果会保存在CSV文件中，并且在控制台输出
