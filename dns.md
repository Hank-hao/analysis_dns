[TOC]

## dns

GoDaddy 建站神器


## 名词解释

- TSIG: Transaction signatures
- TKEY:
- SIG(0)
- DNSSEC Trust Anchors
- QR: 0表示查询报文,1表示响应报文
- Opcode: 通常值为0(标准查询),其他值为1(反向查询)和2(服务器状态请求)
- AA: 表示“授权回答 (authoritative answer)”。该名字服务器是授权于该域的
- TC: 表示“可截断的 (truncated)”。使用UDP时,它表示当应答的总长度超过512字节时,只返回前 512个字节
- RD: 表示“期望递归( recursion desired)”。该比特能在一个查询中设置,并在响应中返回。
- RA: 表示“可用递归”。如果名字服务器支持递归查询,则在响应中将该比 特设置为 1


## 原理



## 配置

```bash

# 父域配置, /var/named/hank.com.zone
hank.com.  IN SOA  admin.hank.com.    admin.hank.com. (
        201802002   ;序列号
        3H          ;刷新时间
        10M         ;重试时间间隔
        1W          ;过期时间
        1D          ;无法解析时否定答案的TTL值
        )

hank.com.      IN   NS   ns1.hank.com.
hank.com.      IN   NS   ns2.hank.com.
ns1.hank.com.  IN   A    192.168.0.1
ns2.hank.com.  IN   A    192.168.0.2

# 子域授权
sub.hank.com      IN   NS   ns1.sub.hank.com.
sub.hank.com      IN   NS   ns2.sub.hank.com.
ns1.sub.hank.com. IN   A    192.168.1.1
ns2.sub.hank.com. IN   A    192.168.1.2


# 子域配置, /etc/named.conf
zone "sub.hank.com." IN {
    type master;
    file "sub.hank.com.zone";
}

# /var/named/sub.hank.com.zone

sub.hank.com  IN SOA ..........
sub.hank.com     IN  NS   ns1.sub.hank.com.
sub.hank.com     IN  NS   ns2.sub.hank.com.
ns1.sub.hank.com. IN   A    192.168.1.1
ns2.sub.hank.com. IN   A    192.168.1.2

# 可以增加父域没有配置的ns, 可以做ns的分布式
sub.hank.com     IN  NS   ns1.xxx.com.
sub.hank.com     IN  NS   ns2.xxx.com.

# ns1.xxx.com.  ns2.xxx.com. 可以配置智能解析, 及多线路不同配置

# ldns从父域拿到ns列表, 从子域也能拿到, 如何取舍?
```

## Feature

### getaddrinfo工作原理
http://www.cnblogs.com/battzion/p/4235562.html

https://www.oschina.net/news/103504/google-public-dns-support-dot

### PTR记录/反向域名解析
- 1.1.1.10.in-addr.arpa.	10	IN	PTR	wangct.xxxx.virtual.
- 应用邮件服务器阻拦垃圾邮件
- rsync默认情况下有反解请求

### TXT记录
- Eureka 用来服务注册
- spf(sender policy framework),防范垃圾邮件,验证邮件服务器是不是指定IP发送过来的
  - 分类: all | ip4 | ip6 | a | mx | ptr | exists | include
  - 前缀: "+"  Pass（通过）;"-"  Fail（拒绝）;"~"  Soft Fail（软拒绝）;"?"  Neutral（中立）
  - xxxx.com. 600 IN TXT "v=spf1 ip4:202.108.14.100 ip4:101.227.12.172 ip4:223.26.72.211 a mx ~all"
  -

### MX记录 
- 电子邮件系统发邮件时根据收信人的地址后缀来定位邮件服务器
- MX记录允许设置一个优先级，当多个邮件服务器可用时，会根据该值决定投递邮件的服务器
- xxxx.com.	 287 IN	MX 20 mx20.xxxx.com.
- xxxx.com.	 287 IN	MX 10 mx1.xxxx.com.

### SRV记录
- 除了记录服务器的地址，还记录了服务的端口
- 并且可以设置每个服务地址的优先级和权重
- rfc2782

```格式
_Service._Proto.Name TTL Class SRV Priority Weight Port Target
Service: 服务名称，前缀“_”是为防止与DNS Label（普通域名）冲突。
Proto:   服务使用的通信协议，_TCP、_UDP、其它标准协议或者自定义的协议。
Name:    提供服务的域名。
TTL:     缓存有效时间。
CLASS:   类别
Priority: 该记录的优先级，数值越小表示优先级越高，范围0-65535。
Weight:   该记录的权重，数值越高权重越高，范围0-65535。     
Port:     服务端口号，0-65535。
Target:   host地址。
```


#### DNSSEC
##### 名词解释
- DNSSEC只是增加了签名,防止篡改, 数据流还是明文
- RRSIG(Resource Record Signature): 资源记录的数字签名
  - 记录类型
  - 算法类型
  - 标签(泛解析中原先 RRSIG 记录的名称)
  - 源TTL
  - 签名失效时间
  - 签名签署时间
  - Key标签(一个简短的数值，用来迅速判断应该用那个 DNSKEY 记录来验证)
  - 签名名称 (用于验证该签名的 DNSKEY 名称)
  - 加密签名
- DNSKEY(DNS Public Key): 存放我们用于检查 DNSSEC 签名的公钥
  - 标识符 (Zone Key (DNSSEC 密钥集) 以及 Secure Entry Point (KSK 和简单密钥集))
  - 协议 (固定值 3 向下兼容)
  - 算法类型 (参考附录「算法类型列表」)
  - 公钥内容
- DS (Delegation Signer): 该记录用于存放 DNSSEC 公钥的散列值
  - Key 标签 (一个简短的数值，用来迅速判断应该用那个 DNSKEY 记录来验证)
  - 算法类型 (参考附录「算法类型列表」)
  - 摘要类型 (创建摘要值的加密散列算法)(参考附录「摘要类型列表」)
  - Digest: A cryptographic hash value of the referenced DNSKEY-record.
- NSEC(Next Secure): 用于验证不存在的资源记录
- ZSK(Zone-Signing Key):一种短期密钥,ZSK 对 DNS 记录进行签名,无须与上层通讯
- KSK(Key-Signing Key):一种长期密钥,KSK 对 ZSK 进行签名

##### 报文中新增的标志
- DO: DNSSEC ok.支持DNSSEC的解析服务器在它的DNS查询报文中，必须把DO标志位置1，否则权威域服务器认为解析器不支持DNSSEC就不会返回RRSIG等记录
- AD: Authentic Data,认证数据标志，如果服务器验证了DNSSEC相关的数字签名，则置AD位为1，否则为0
- CD: Checking Disabled,关闭检查标志位用于支持DNSSEC验证功能的解析器（validating security-aware resolver）和递归域名服务器之间，解析器在发送请求时把CD位置1，服务器就不再进行数字签名的验证而把递归查询得到的结果直接交给解析器，由解析器自己验证签名的合法性。

### 软件工具
- ISC(internet systems consortium): https://www.isc.org
  - Bind
- NLnet Labs: https://nlnetlabs.nl
  - NSD: the authoritative nameserver
  - Unbound: the validating recursive resolver
  - OpenDNSSEC: the policy-based signer 
- cz.nic: https://www.nic.cz/
  - 由捷克主要的网际网络服务供应商(ISP)所组成的非营利协会,捷克顶级域名注册
  - 开源地址: https://github.com/CZ-NIC
  - knot: **authoritative-only DNS server**
- DNS测试
  - https://dnsflagday.net/?from=timeline&isappinstalled=0
- sendip工具
```
SENDIP 是一个LINUX 下的命令行工具，可以通过命令行参数的方式发送各种格式的IP 包，它有大量的命令行参数来规定各种协议的头格式，
目前可支持NTP, BGP, RIP, RIPng,TCP, UDP, ICMP 或raw IPv4 和IPv6 包格式，并且可以随意在包中添加数据。
```
### 参考资料
- https://www.iana.org/dnssec
- https://developers.google.com/speed/public-dns/
- andriod与google pulibc dns之间的加密通讯方式
  - https://www.oschina.net/news/103504/google-public-dns-support-dot
- https://www.icann.org/resources/pages/dns-resolvers-checking-current-trust-anchors-2018-06-28-zh
### FAQ
- zone文件每次更新要重新签名
- 512问题
```
由于历史原因，互联网物理链路最小MTU=576, 所有DNS限制UDP报文小于576，限制在512
DNS UDP包没有字段标识报文ID，所以多余的数据只能被抛弃
```
- DNSSEC的用处
```
  - 配置安全的域名解析服务器(Resolver)，该服务器可以保护使用它的用户，防止被DNS欺骗攻击。这里只涉及数字签名的验证工作
  - 配置安全的权威域名服务器(Name Server)，对权威域的资源记录进行签名，保护服务器不被域名欺骗攻击
  - DLV旁路认证概念
- 取消其AUTHORITY、 ADDITIONAL的返回,节省时间反复去查询权威服务器。如cp31.ott.cibntv.net 
```
- knot bug, 时间戳做随机数种子计算id，id后有增加操作, 导致id溢出
- knot bug, 文件句柄关闭多次,产生abort


## 工程

```
头条/抖音域名授权在阿里
google/facebook 全部使用anycast ip

联通/电信/海外akamai都对接了流量清洗
akamai通过sflow获取端口流量, 到达某一阈值后发布明细路由，将入流量通过akamai引入

urpf问题
URPF（Unicast Reverse Path Forwarding）反向路径转发,防止基于源地址的网络攻击行为
loose, strict 模式
国内运营商去掉，国外一般不配置

httpdns 改成 anycast ip

onlinelab, web server + dns 权威
1. 访问url
2. 生成唯一id，随机域名
3. 返回html,js
4. js执行，访问页面，调度，vrs，随机域名
5. 用户发起查询, 检测结果的请求

```
### 云解析
```
云解析 PrivateZone
基于阿里云专有网络VPC（Virtual Private Cloud）环境的私有域名解析和管理服务
您能够在自定义的一个或多个专有网络中将私有域名映射到IP资源地址, 同时在其他网络环境无法访问您的私有域名


```

### 实施
- baishan
```
bsgslb.com
v.bsgslb.com
qingcloud.com   //不是青云的吗?
solocdn.cn.

```
- akamai
```
```
- qq
```

```

- 海外
40w, ldns
探测频率可根据访问量及频率量级
ping + traceroute最后rtt(<3跳, 不可信)
ipv6的量, 不较少
成本分档, 质量分档
节点探测ldns
ttl:  20s
劫持情况: 很少
基于as调度

国外:
- ldns用错, 服务节点使用ANYCAST
- 抗攻击(专打一个点)


### ipv6

- 通常不会配置默认线路的AAAA记录, 因为许多解析器会优先使用AAAA记录, 而v6节点数量有限, 链路质量未知, 会导致带宽非预期

##  FAQ

### 域名规范
字符, 字母, 中划线
中文等其它语言?

### 请求内容超过1000个字节，server返回trunc, 

### 泛域名配置
``` bash

# 泛域名标准行为
*.a.com A 1.1.1.1
dig b.a.com 返回 1.1.1.1
dig c.b.a.com 返回 1.1.1.1

# 泛域名配置后，又配置了明细域名, 会按照明细域名解析, 但是明细域名的下一级域名会返回nxdomain
# 标准bind行为, 私有dns已优化
*.a.com A 1.1.1.1
b.a.com A 2.2.2.2
dig b.a.com 返回 2.2.2.2
dig c.b.a.com 返回nxdomain

# 泛域名配置，某个子域也是泛域名
*.a.com
*.b.a.com
dig b.a.com  # 无结果, 最长匹配到*.b.a.com, 但是无子域, 无法返回结果， 标准bind行为, 私有dns已优化

```

### ECS
- 权威一般都支持, 权威一般不缓存, 不需要多大的空间
- Cache需要缓存不同子网的结果
- https://developers.google.com/speed/public-dns/docs/ecs
- https://tools.ietf.org/html/rfc7871=

### 请求zone的ns记录才会返回结果

### buf溢出
dig @140.249.248.37 "<グリュンランド　クリームチーズ　ペッパー.test-hk-live.ks-cdn.com."

### cnamex 
bind不识别多cname情况
自己实现多cname, 权威按比例给出唯一的cname

### 域名劫持
- 使 ecs 失效?

### 公共DNS
- 223.5.5.5, 223.6.6.6
- 119.29.29.29
- 114.114.114.114, 不支持ecs

### 多named进程,导致解析错乱
- 为啥会存在多进程的情况

### 公共dns返回127.0.0.1的情况
- 114.114.114.114与8.8.8.8 对不存在的域名第一次返回nxdomain
- 相同域名后续会返回 127.0.0.1
- 可能是针对黑名单中的设备采集的策略

### 小运营商解析问题

- 向不同公共ldns请求，可能会得到不同的结果，因为出口可能不同


### 运营商Local DNS行为

- 减少压力, 增加TTL


### nxdomain

- 一条记录都没有才会返回, 有记录不会返回, 如配置AAAA, 无A, 请求A返回NOERROR

### cname查询

```bash
dig www.a.com cname  # 查询到cname就不会继续查找了, cname还有cname也不会; a记录查询如果没有结果,会递归查询
```


## Ref

- https://www.bind9.net/download
- https://intodns.com/ywings.com
- RFC: https://rfcs.io/dns
