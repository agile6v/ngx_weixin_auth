About
=====

此模块用于 "[微信公共平台认证 and 微信消息接收验证](http://mp.weixin.qq.com/wiki/index.php?title=%E9%AA%8C%E8%AF%81%E6%B6%88%E6%81%AF%E7%9C%9F%E5%AE%9E%E6%80%A7 "weixin auth")", 配置了此模块以后应用服务器就不需要对每条用户消息进行验证。


Sample Configuration
=====
    location /weixin {
            weixin_auth on;
            weixin_auth_token agile6v;
            proxy_pass http://tomcat_server/servelt;
    }

See also
=====
[weixin-simulator](https://github.com/ushuz/weixin-simulator)（很好用的调试工具）

