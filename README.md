为了解决现有内网穿透与反向代理工具的局限性，实现对内网设备的远程调用需求，遂写了这个小工具。该工具通过邮件加密传输机制，实现对处于内网环境的设备的安全、间接调用。

工具包含以下主要功能：

1. **密钥派生与数据加密**：基于用户设置的密钥，利用 AES 算法对传输数据进行加密，确保数据的完整性与安全性。
2. **邮件传输**：支持通过 SMTP 协议发送加密后的序列化数据到指定邮箱。
3. **邮件接收与解析**：使用 IMAP 协议从邮箱中获取加密邮件并解密内容，从而提取并反序列化数据。
4. **个人资源调用**：可编写通用方法，调用个人PC资源。

### 快速开始

1. **初始化工具**：创建 `EmailUtility` 实例，提供邮箱账号、密码和密钥。
2. **发送加密数据**：调用 `send_serialized_data()` 方法发送数据至目标邮箱。
3. **接收并解密数据**：调用 `fetch_latest_emails()` 方法从收件箱中提取并解析邮件内容。

**示例代码**：

```python
email_utility = EmailUtility(EMAIL_ACCOUNT, EMAIL_PASSWORD, ENCRYPTION_KEY)
email_utility.send_serialized_data(recipient_email, subject='Test', data={'key': 'value'})
emails = email_utility.fetch_latest_emails(num_emails=5)
```