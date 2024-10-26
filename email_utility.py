import pickle
import smtplib
import logging
import base64
import imaplib
import email
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from email.header import decode_header
from typing import Optional

from cryptography.hazmat.primitives import hashes, padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.backends import default_backend
import os


# 邮箱配置，请根据实际情况填写

class EmailUtility:
    def __init__(self, sender_email, sender_password, encryption_key, smtp_server: Optional[str] = 'smtp.126.com',
                 imap_server: Optional[str] = 'imap.126.com'):
        self.smtp_server = smtp_server
        self.imap_server = imap_server
        self.sender_email = sender_email
        self.sender_password = sender_password
        self.encryption_key = self.derive_key(encryption_key)
        self.mail = None  # IMAP连接对象

    def derive_key(self, password):
        # 使用 PBKDF2 算法从密码中派生密钥
        salt = b'\x01' * 16  # 固定盐值（注意：在生产环境中应使用随机盐值并保存）
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=100000,
            backend=default_backend()
        )
        key = kdf.derive(password.encode())
        return key

    def encrypt_data(self, data):
        # 序列化数据
        serialized_data = pickle.dumps(data)

        # 初始化加密器
        iv = os.urandom(16)  # 生成随机 IV
        cipher = Cipher(algorithms.AES(self.encryption_key), modes.CBC(iv), backend=default_backend())
        encryptor = cipher.encryptor()

        # 添加填充
        padder = padding.PKCS7(128).padder()
        padded_data = padder.update(serialized_data) + padder.finalize()

        # 加密数据
        encrypted_data = encryptor.update(padded_data) + encryptor.finalize()

        # 将 IV 和加密数据一起返回
        return iv + encrypted_data

    def decrypt_data(self, encrypted_data):
        # 将 Base64 编码的数据解码
        encrypted_data = base64.b64decode(encrypted_data)

        # 提取 IV
        iv = encrypted_data[:16]
        encrypted_payload = encrypted_data[16:]

        # 初始化解密器
        cipher = Cipher(algorithms.AES(self.encryption_key), modes.CBC(iv), backend=default_backend())
        decryptor = cipher.decryptor()

        # 解密数据
        padded_data = decryptor.update(encrypted_payload) + decryptor.finalize()

        # 移除填充
        unpadder = padding.PKCS7(128).unpadder()
        data = unpadder.update(padded_data) + unpadder.finalize()

        # 反序列化数据
        original_data = pickle.loads(data)
        return original_data

    def send_serialized_data(self, recipient_email, subject, data):
        """
        将加密后的序列化数据发送到指定邮箱。
        """
        try:
            # 加密数据
            encrypted_data = self.encrypt_data(data)

            # 将加密数据进行 Base64 编码
            encoded_data = base64.b64encode(encrypted_data).decode('utf-8')

            # 设置 SMTP 服务器
            server = smtplib.SMTP(self.smtp_server)
            server.starttls()

            # 登录
            server.login(self.sender_email, self.sender_password)

            # 创建邮件
            msg = MIMEMultipart()
            msg['From'] = self.sender_email
            msg['To'] = recipient_email
            msg['Subject'] = subject

            # 添加加密后的数据作为邮件正文
            msg.attach(MIMEText(encoded_data, 'plain'))

            # 发送邮件
            text = msg.as_string()
            server.sendmail(self.sender_email, recipient_email, text)

            logging.info("邮件发送成功!")
        except Exception as e:
            logging.error(f"发送邮件时出错: {str(e)}")
            raise e
        finally:
            # 关闭连接
            server.quit()

    def connect_to_imap(self):
        try:
            logging.info("登录成功")
            self.mail = imaplib.IMAP4_SSL(self.imap_server)
            imaplib.Commands['ID'] = ('NONAUTH', 'AUTH', 'SELECTED')
            args = ("name", "imaplib", "version", "1.0.0")
            self.mail._simple_command('ID', '("' + '" "'.join(args) + '")')
            self.mail.login(self.sender_email, self.sender_password)
            logging.info("IMAP 服务器登录成功")
        except Exception as e:
            logging.error(f"连接到 IMAP 服务器时出错: {str(e)}")
            raise e

    def fetch_latest_emails(self, num_emails=5):
        """
        获取最新的未读邮件列表。
        """
        if not self.mail:
            self.connect_to_imap()
        try:
            # 选择收件箱
            status, messages = self.mail.select('INBOX')

            if status != 'OK':
                logging.error(f"无法选择收件箱: {messages}")
                return []

            # 搜索所有未读邮件
            _, message_numbers = self.mail.search(None, 'UNSEEN')
            email_ids = message_numbers[0].split()

            emails = []
            for num in email_ids[:num_emails]:
                _, msg_data = self.mail.fetch(num, '(RFC822)')
                for response_part in msg_data:
                    if isinstance(response_part, tuple):
                        email_body = response_part[1]
                        email_message = email.message_from_bytes(email_body)
                        subject, encoding = decode_header(email_message["Subject"])[0]
                        if isinstance(subject, bytes):
                            subject = subject.decode(encoding or "utf-8")
                        sender = email_message["From"]
                        emails.append({"subject": subject, "sender": sender, "message": email_message})

            logging.info(f"成功获取了 {len(emails)} 封未读邮件")

            return [self.parse_email_content(x) for x in emails]
        except Exception as e:
            logging.error(f"获取邮件时出错: {str(e)}")
            self.connect_to_imap()
            return []

    def parse_email_content(self, email_dict):
        """
        解析邮件内容，提取主题、发件人、收件人、日期、正文和反序列化的数据。
        """
        email_message = email_dict['message']
        # subject = email_message['Subject']
        # from_email = email_message['From']
        # to_email = email_message['To']
        # date = email_message['Date']

        # 获取邮件正文
        body = None
        if email_message.is_multipart():
            for part in email_message.walk():
                content_type = part.get_content_type()
                content_disposition = str(part.get("Content-Disposition"))
                if content_type == 'text/plain' and 'attachment' not in content_disposition:
                    body_bytes = part.get_payload(decode=True)
                    body = body_bytes.decode()
                    break
        else:
            body_bytes = email_message.get_payload(decode=True)
            body = body_bytes.decode()

        # 解密并反序列化数据
        data = None
        try:
            data = self.decrypt_data(body)
        except Exception as e:
            logging.error(f"解密并反序列化数据时出错: {str(e)}")
        # {
        #     'subject': subject,
        #     'from': from_email,
        #     'to': to_email,
        #     'date': date,
        #     'body': body,
        #     'data': data
        # }
        return data


if __name__ == "__main__":
    EMAIL_ACCOUNT = ''
    EMAIL_PASSWORD = ''
    ENCRYPTION_KEY = 'your_secret_key'  # 对称加密密钥

    email_utility = EmailUtility(EMAIL_ACCOUNT, EMAIL_PASSWORD, ENCRYPTION_KEY)
    data = {'test2': 'value1', 'key2': 'value2'}

    # 发送加密的序列化数据
    try:
        email_utility.send_serialized_data(
            recipient_email=EMAIL_ACCOUNT,
            subject='python_from_bot',
            data=data
        )
    except Exception as e:
        print(f"发送邮件失败: {e}")

    # 接收并解析邮件
    try:
        emails = email_utility.fetch_latest_emails(num_emails=5)
        for email in emails:
            print(f"解析邮件内容: {email}")
            # 在此处处理解析后的内容，例如调用第三方 API
            # call_third_party_api(content)
    except Exception as e:
        print(f"获取或解析邮件失败: {e}")
