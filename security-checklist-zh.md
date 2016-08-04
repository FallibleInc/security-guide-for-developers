[返回目录](README-zh.md)


### 安全checklist   

##### 权限系统 (注册/注册/二次验证/密码重置) 
- [ ] 任何地方都使用HTTPS.
- [ ] 使用`Bcrypt`存储密码哈希 (没有使用盐的必要 - `Bcrypt` 干的就是加密这个事情).
- [ ] `登出`之后销毁会话ID .  
- [ ] 密码重置后销毁所有活跃的会话.  
- [ ] OAuth2 验证必须包含 `state` 参数.
- [ ] 登陆成功之后不能直接重定向到开放的路径（需要校验，否则容易存在钓鱼攻击）.
- [ ] 当解析用户注册/登陆的输入时，过滤 javascript://、 data:// 以及其他 CRLF 字符. 
- [ ] 使用 secure/httpOnly cookies.
- [ ] 移动端使用`OTP`验证时，当调用`generate OTP` 或者 `Resend OTP` API时不能吧OTP（One Time Password）直接返回。（一般是通过发送手机验证短信，邮箱随机code等方式，而不是直接response）  
- [ ] 限制单个用户`Login`、`Verify OTP`、 `Resend OTP`、`generate OTP`等API的调用次数，使用Captcha等手段防止暴力破解.  
- [ ] 检查邮件或短信里的重置密码的token，确保随机性（无法猜测）  
- [ ] 给重置密码的token设置过期时间.
- [ ] 重置密码成功后，将重置使用的token失效.


##### 用户数据和权限校验  
- [ ] 诸如`我的购物车`、`我的浏览历史`之类的资源访问，必须检查当前登录的用户是否有这些资源的访问权限。  
- [ ] 避免资源ID被连续遍历访问，使用`/me/orders` 代替 `/user/37153/orders` 以防你忘了检查权限，导致数据泄露。   
- [ ] `修改邮箱/手机号码`功能必须首先确认用户已经验证过邮箱/手机是他自己的。  
- [ ] 任何上传功能应该过滤用户上传的文件名，另外，为了普适性的原因（而不是安全问题），上传的东西应该存放到例如S3之类的云存储上面，而不是存储在这几的服务器，防止代码执行。  
- [ ] `个人头像上传` 功能应该过滤所有的 `EXIF` 标签，即便没有这个需求.  
- [ ] 用户ID或者其他的ID，应该使用 [RFC compliant ](http://www.ietf.org/rfc/rfc4122.txt) 的`UUID` 而不是整数. 你可以从github找到你所用的语言的实现.  
- [ ] [JWT（JSON Web Token）](https://jwt.io/)很棒.当你需要做一个单页应用/API的使用使用.  


##### 安卓和iOS APP
- [ ] 支付网关的 `盐（salt）` 不应该硬编码  
- [ ] 来自第三方的 `secret` 和 `auth token` 不应该硬编码  
- [ ] 在服务器之间调用的API不应该在app里面调用  
- [ ] 在安卓系统下，要小心评估所有申请的 [权限](https://developer.android.com/guide/topics/security/permissions.html)   
- [ ] 在iOS系统下，使用系统的钥匙串来存储敏感信息（权限token，api key等等）。 __不要__ 把这类信息存储在用户配置里面  
- [ ] 强烈推荐[证书绑定（Certificate pinning）](https://en.wikipedia.org/wiki/HTTP_Public_Key_Pinning)   


##### 安全头信息和配置  
- [ ] `添加` [CSP](https://en.wikipedia.org/wiki/Content_Security_Policy) 头信息，减缓 XSS 和数据注入攻击. 这很重要.  
- [ ] `添加` [CSRF](https://en.wikipedia.org/wiki/Cross-site_request_forgery) 头信息防止跨站请求调用（CSRF）攻击.同时`添加` [SameSite](https://tools.ietf.org/html/draft-ietf-httpbis-cookie-same-site-00) 属性到cookie里面.  
- [ ] `添加` [HSTS](https://en.wikipedia.org/wiki/HTTP_Strict_Transport_Security) 头信息防止SSL stripping攻击.
- [ ] `添加` 你的域名到 [HSTS 预加载列表](https://hstspreload.appspot.com/)
- [ ] `添加` [X-Frame-Options](https://en.wikipedia.org/wiki/Clickjacking#X-Frame-Options) 防止点击劫持.  
- [ ] `添加` [X-XSS-Protection](https://www.owasp.org/index.php/OWASP_Secure_Headers_Project#X-XSS-Protection) 缓解XSS攻击.  
- [ ] `更新`DNS记录，增加 [SPF](https://en.wikipedia.org/wiki/Sender_Policy_Framework) 记录防止垃圾邮件和钓鱼攻击.  
- [ ] 如果你的Javascript 库存放在第三方的CDN上面，需要`添加` [内部资源集成检查](https://en.wikipedia.org/wiki/Subresource_Integrity) 。为了更加安全，添加[require-sri-for](https://w3c.github.io/webappsec-subresource-integrity/#parse-require-sri-for) CSP-directive 就不会加载到没有SRI的资源。  
- [ ] 使用随机的CSRF token，业务逻辑API可以暴露为POST请求。不要把CSRF token通过http接口暴露出来比如第一次请求更新的时候。  
- [ ] 在get请求参数里面，不要使用临界数据和token。 暴露服务器日志的同时也会暴露用户数据。
  
  
##### 过滤输入  
- [ ] 所有暴露给用户的参数输入都应该 `过滤` 防止 [XSS](https://en.wikipedia.org/wiki/Cross-site_scripting) 攻击.
- [ ] 使用参数化的查询防止 [SQL 注入](https://en.wikipedia.org/wiki/SQL_injection).  
- [ ] 过滤所有具有功能性的用户输入，比如`CSV导入`    
- [ ] `过滤`一些特殊的用户输入，例如将robots.txt作为用户名，而你刚好提供了 coolcorp.io/username 之类的url来提供用户信息访问页面。（此时变成 coolcorp.io/robots.txt，可能无法正常工作）  
- [ ] 不要自己手动拼装JSON字符串，不管这个字符串有多么小。请使用你所用的语言相应的库或者框架来编写。  
- [ ] `过滤` 那些有点像URL的输入，防止 [SSRF](https://docs.google.com/document/d/1v1TkWZtrhzRLy0bYXBcdLUedXGb9njTNIJXa3u9akHM/edit#heading=h.t4tsk5ixehdd) 攻击  
- [ ] 输出显示给用户之前需要`过滤`，防止XSS攻击.

##### 操作  
- [ ] 如果你的业务很小或者你缺乏经验，可以评估一下使用AWS或者一个PaaS平台来运行你的代码  
- [ ] 在云上使用正规的脚本创建虚拟结  
- [ ] 检查所有机器没有必要开放的`端口`  
- [ ] 检查数据库是否没有密码或者使用默认密码，特别是MongoDB和Redis  
- [ ] 使用SSH登录你的机器，不要使用密码，而是使用 SSH key 验证来登录  
- [ ] 及时更新系统，防止出现0day漏洞，比如Heartbleed、Shellshock等  
- [ ] 修改服务器配置，HTTPS使用TLS1.2，禁用其他的模式。(值得这么做)
- [ ] 不要在线上开启DEBUG模式，有些框架，DEBUG模式会开启很多权限或者后门，或者爆楼一些敏感数据到错误栈信息里面  
- [ ] 对坏人和DDOS攻击要有所准备，选择那些提供DDOS清洗的主机服务  
- [ ] 监控你的系统，同时写到日志里面 (例如使用 [New Relic](https://newrelic.com/) ).
- [ ] 如果是2B的业务，坚持顺从需求。如果使用AWS S3,可以考虑使用 [数据加密](http://docs.aws.amazon.com/AmazonS3/latest/dev/UsingServerSideEncryption.html) 功能. 如果使用AWS EC2，考虑使用磁盘加密功能（现在系统启动盘也能加密了）  

##### 关于人  
- [ ] 开一个邮件组和搜集页面，方便安全研究人员提交漏洞  
- [ ] 信任你所创造的东西，限制用户数据库的访问  
- [ ] 对报告bug、漏洞的人有礼貌
- [ ] 将你的代码给那些有安全编码观念的同伴review (More eyes)
- [ ] 出现被黑或者数据泄露是，检查数据访问前的日志，让相关的人改密码。你可能需要外部的机构来帮助审计  
- [ ] 设置 [Netflix Scumblr](https://github.com/Netflix/Scumblr) 及时了解你的组织（公司）在社交网络或者搜索引擎上的一些讨论信息  
