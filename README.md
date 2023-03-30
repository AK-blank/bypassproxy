## 代理模块
目前实现的代理:

1. HTTP
2. socks4
3. socks5

## 绕过功能

1. HTTP代理:HTTP/s流量分片
2. socks代理:全流量分片

## 思维风暴

- [x] TCP应用层绕过数据传输分段
- [ ] 通过RAW socket实现TCP层
- [ ] 通过RAW socket实现IP层(成本太高,且效果不一定好,暂时放弃)

以下方法需要自己实现RAW Socket

- [ ] IP分片(成本太高,且效果不一定好,暂时放弃)



- [ ] 混入大量KEEP-Alive

```
原理:
	与随机间隔时长原理类似
```



- [ ] 随机间隔时长

```
原理:
	IDS/IPS不可能永远等待,只要该时间间隔能够保证到达服务但却被IDS/IPS等放弃即可达到绕过.
```



- [ ] 快速重传

```
原理:
	在发送真实数据前先发送多次无用数据包,并将真实数据隐藏在后续的快速重传数据包中
	
	这个和错误checksum有点像,需要后续确认
```



- [x] URG标志位为1

```
原理:
	TCP协议通过可以指定数据偏移来告诉服务器真实的数据起始位置,如果IDS/IPS没有实现该功能即可产生绕过
	经过测试,目前Urgent Pointer 只在设置为1时有效
	但各种资料中所描述的是一个指针,按理来说应该是任意大小的,还需要后续读TCP/IP详解
```



- [x] 错误CheckSum

```
原理:
	将checksum计算错误,在真实服务器环境下,错误的包将不会收到响应,而IDS可能没有实现check检查的功能导致误接收这部分payload,从而影响解码
	经过测试可行
```



- [ ] 保留

  

无效绕过:


- [x] 三次握手携带数据

```
原理:
	三次握手中携带payload,可能会让IDS将这部分数据与真实数据混合在一起,导致解码错误
	已测试,不影响解码
```

- [x] 错误序列号+FIN/RST

```
原理:
	没有实现状态跟踪的IDS/IPS在接收数据时,可能会误以为连接已经结束
已测试,无法绕过探针
```

- [x] 错误序列号

```
原理:
	错误的序列号可能会导致实现了状态跟踪的IDS/IPS在跟踪过程中将有效的数据包丢弃

已测试,无法绕过探针
```





## 研究过程



```
https://pkg.go.dev/golang.org/x/net 这个库的功能很强大,后续多关注
```

```
runtime.GOOS 用于获取操作系统是什么
系统底层的一些预置值,存放在syscall\types_windows.go中,例如socket编程涉及到的关键字
```



```


syscall.AF_INET，表示服务器之间的网络通信
syscall.AF_UNIX表示同一台机器上的进程通信
syscall.AF_INET6表示以IPv6的方式进行服务器之间的网络通信

syscall.SOCK_RAW，表示使用原始套接字，可以构建传输层的协议头部，启用IP_HDRINCL的话，IP层的协议头部也可以构造，就是上面区分的传输层socket和网络层socket。
syscall.SOCK_STREAM, 基于TCP的socket通信，应用层socket。
syscall.SOCK_DGRAM, 基于UDP的socket通信，应用层socket。

IPPROTO_TCP 接收TCP协议的数据
IPPROTO_IP 接收任何的IP数据包
IPPROTO_UDP 接收UDP协议的数据
IPPROTO_ICMP 接收ICMP协议的数据
IPPROTO_RAW 只能用来发送IP数据包，不能接收数据。

syscall.IPPROTO_RAW == (int)255
```



### TCP CheckSum

最近在尝试用Go写TCP RAW Socket,所以就想自己实现TCP协议的各个过程

**基于net.Dial("ip4:tcp", Dip)**这个函数实现,不需要自定义ip头,只需要自定义TCP头即可

在找了很多资料(懒得翻TCP/IP详解了),终于看到checksum的实现机制

踩了两天坑,这部分排查起来是真的麻烦,一旦checksum错了服务端就没反应,简直怀疑人生

大致原理如下:

```go
IPv4 SRC + IPv4 DST + IPv4 Protocol(对应TCP即为0x0006) + TCP Segment Length +
TCP Header (checksum字段设为0) + TCP Options + TCP Payload

其中:TCP Segment Length 表示TCP头部的长度+TCP payload的长度

将上述字段以2bytes为一个单位进行相加,最后超出2bytes的大小范围的数拿出来加到最后去.
至于为什么是2bytes,这是因为在TCP协议的定义中Checksum字段的大小固定为2bytes

使用GO计算的大致过程如下,该函数是根据网上C语言实现的原理改写得到

func Checksum(buffer []byte, size uint32) uint16 {

	var checksum uint32
	for i:=0; size > 0; i += 2{
		checksum += uint32(buffer[i]) + uint32(buffer[i+1])<<8
		size -= 2
	}
	checksum = checksum>>16 + (checksum & 0xffff)
	checksum += checksum >> 16
	return (uint16(checksum ^ 0xffff ))
}

使用后发现还存在一些小问题,就是计算出来的数值没有和Go中的net.Dial发送的大小端序对其,当然也可以说是我算的不对.但是后面也懒得改了,就用了个笨办法将其byte位进行调换即可.

```

参考连接:

```
https://stackoverflow.com/questions/66142461/tcp-calculate-checksum#comment127123952_66161909
```





### 系统自动返回RST

接着上回说,成功发送SYN包后也收到了服务端响应的ACK,但是还没来得及进行下一步的时候,系统就自动给服务端回复了一个RST导致连接中断了.

查阅了许多资料,关于这个问题的回复基本是: RAW socket所发出的流量没有经过系统内核的协议栈,所以系统并不知道我们发送了SYN包,但是却能接收到来自服务端的ACK包,于是乎系统协议栈觉得莫名其妙,就给服务端发送了一个RST包,关闭了连接.

解决办法:

?	1.修改系统内核,(具体如何实现,这里不进行讨论)

?	2.屏蔽系统发出的RST包.



针对第二个办法的解决方法:

方法一: 通过iptables屏蔽系统的RST包

优点:方便

缺点:万一linux系统中没有iptables呢?虽然iptables是集成在系统内核里的,一般都有吧.

```shell
添加规则
sudo iptables -t filter -I OUTPUT -p tcp --dport 80 --tcp-flags RST RST -j DROP

删除规则
sudo iptables -t filter -D OUTPUT -p tcp --dport 80 --tcp-flags RST RST -j DROP

```

添加一点细节,最后体现在go中:至于为什么写这么严格的规则,大家想一下Syn Flood的攻击原理,虽然我们用的基本都是本地机器,但要是你在服务器上把RST给过滤了,那就麻烦咯.

```
	ruleAdd := fmt.Sprintf("iptables -t filter -I OUTPUT -p tcp -s %s --sport %d -d %s --dport %d  --tcp-flags RST RST -j DROP",sip,sport,dip,dport)
	ruleDel := fmt.Sprintf("iptables -t filter -D OUTPUT -p tcp -s %s --sport %d -d %s --dport %d  --tcp-flags RST RST -j DROP",sip,sport,dip,dport)
	err = exec.Command("/bin/bash","-c",ruleAdd).Run()
	if err != nil {
		log.Fatal(err)
		return
	}
	//TCP流结束时删除相关iptables的规则.
	defer func(command *exec.Cmd) {
		err := command.Run()
		if err != nil {

		}
	}(exec.Command("/bin/bash", "-c", ruleDel))
```



方法二:自己通过IP层实现一个RST包过滤器.

优点:啥时候都管用

缺点:自己动手写麻烦!



参考连接:

https://stackoverflow.com/questions/1188951/in-raw-socket-programming-on-linux-how-can-i-prevent-the-underlying-os-from-res