package byProxy

import (
	"BypassProxy/TCP"
	"fmt"
	"log"
	"net"
	"net/url"
	"regexp"
	"strings"
	"sync"
)

//http代理模式
//参数:host,port,请求头混淆标志位
//http代理核心处理逻辑
func http_Proxy(clientConn net.Conn, clientData string, maxLen int, fregmentFlag, methodMixing,ECS,URG bool) {
	//httpsRealIp := ""
	//httpsRealPort := ""
	//目前https部分稳定性较差,需要后续优化
	//已优化完成
	datalen := len(clientData)
	if datalen < 7 {
		log.Println("我小于7:", clientData)
		return
	}
	first_line_reg,_ := regexp.Compile(`^[A-Z]{3,}\x20[^\x0a\x0d]+\x20HTTP\b`)
	first_line := first_line_reg.FindString(clientData)
	//log.Println(clientData)
	var method, URL, address string
	// 从客户端数据读入 method，url
	fmt.Sscanf(first_line, "%s%s", &method, &URL)

	hostPortURL, err := url.Parse(URL)
	if err != nil {
		log.Println(err)
		return
	}
	// 如果方法是 CONNECT，则为 https 协议
	if method == "CONNECT" {
		address = hostPortURL.Scheme + ":" + hostPortURL.Opaque
	} else { //否则为 http 协议
		address = hostPortURL.Host
		// 如果 host 不带端口，则默认为 80
		if strings.Index(hostPortURL.Host, ":") == -1 { //host 不带端口， 默认 80
			address = hostPortURL.Host + ":80"
		}
	}
	if method == "CONNECT" { //该部分是为了区分http代理http协议和HTTPS协议的情况
		//No.1 tls协议如果想像http进行针对性分段的话,就需要实现证书解密数据.
		//No.2 否则只能退而求其次针对tls协议的流量进行分段,目前采用该方案,可行
		//No.3 最差情况下只做单纯的转发
		realconn, err := TCP.TcpDial(address)

		if err != nil {
			return
		}

		log.Println("HTTP Proxy TLS for:", realconn.Rawconn.RemoteAddr())
		_, err = clientConn.Write([]byte("HTTP/1.1 200 Connection established\r\n\r\n"))
		if err != nil {
			return
		}
		//realconn.TCP_ECS_Flag = true
		/*
			https://www.baidu.com
		*/
		//bufWriter := new(bytes.Buffer)
		//log.Println("卡1",time.Now())
		realconn.TCP_ECS_Flag = ECS
		realconn.TCP_URG_Flag = URG
		realconn.TCP_Frag_Flag = fregmentFlag
		realconn.TCP_Frag_Len = maxLen
		realconn.RawCopy(clientConn)

	} else { // 这部分为http协议才进入的逻辑
		httpProxy_2_HTTP(clientConn, clientData,address, maxLen, fregmentFlag, methodMixing,ECS,URG)
	}
}

//如果是HTTP请求则直接将请求转发给目标
func httpProxy_2_HTTP(clientConn net.Conn, clientData,address string, maxLen int, fregmentFlag, methodMixing,ECS,URG bool) {

	realconn, err := TCP.TcpDial(address)
	if err != nil {
		//log.Println(err)
		//if realconn.Misc_iptable{
		//	err = realconn.CloseRst()
		//	if err != nil {
		//		return
		//	}
		//}
		return
	}
	//defer

	log.Println("HTTP Proxy for:", realconn.Rawconn.RemoteAddr())

	realconn.TCP_ECS_Flag = ECS
	realconn.TCP_URG_Flag = URG
	realconn.TCP_Frag_Flag = fregmentFlag
	realconn.TCP_Frag_Len = maxLen

	//log.Println(clientData)

	realconn.WriteData([]byte(clientData))
	TCP.R2T(realconn, clientConn)
	realconn.Close()
	//一次代理请求流程走完,后续还需要考虑一条流中多个会话的问题,请求的目的服务器可能不一致需要修改的.
	defer func() {
		clientConn.Close()
		//log.Println("退出http代理")
	}()
	if strings.Contains(clientData,"keep-alive"){
		//doneFlag := make(chan int,1)
		var wd sync.WaitGroup
		for {
			byteclientData := make([]byte,0)
			for {
				cache, err := getMaxData(clientConn)
				if err!= nil{
					//log.Println("获取数据失败",err)
					return
				}
				if len(cache)!=0{
					byteclientData = append(byteclientData, cache...)
					break
				}

			}
			for i:=0;i<2;i++{
				if string(byteclientData[len(byteclientData)-4:]) != "\r\n\r\n"{
					cache, _ := getMaxData(clientConn)
					byteclientData = append(byteclientData, cache...)
				}else {
					break
				}
			}
			if len(byteclientData) != 0{
				clientData = string(byteclientData)
				datalen := len(clientData)
				if datalen < 7 {
					log.Println("我小于7:", clientData)
					return
				}
				first_line_reg,_ := regexp.Compile(`^[A-Z]{3,}\x20[^\x0a\x0d]+\x20HTTP\b`)
				first_line := first_line_reg.FindString(clientData)
				//log.Println(clientData)
				var method, URL string
				// 从客户端数据读入 method，url
				fmt.Sscanf(first_line, "%s%s", &method, &URL)

				hostPortURL, err := url.Parse(URL)
				if err != nil {
					log.Println("解析失败",err)
					return
				}
				address = hostPortURL.Host
				// 如果 host 不带端口，则默认为 80
				if strings.Index(hostPortURL.Host, ":") == -1 { //host 不带端口， 默认 80
					address = hostPortURL.Host + ":80"
				}
				wd.Add(1)
				go httpProxy_2_HTTP_once(clientConn, clientData, address,&wd,maxLen, fregmentFlag,ECS,URG)
			}
			wd.Wait()
		}

	}



}

func httpProxy_2_HTTP_once(clientConn net.Conn, clientData,address string,wd *sync.WaitGroup,maxLen int, fregmentFlag,ECS,URG bool) {

	realconn, err := TCP.TcpDial(address)
	if err != nil {
		//log.Println(err)
		//if realconn.Misc_iptable{
		//	err = realconn.CloseRst()
		//	if err != nil {
		//		return
		//	}
		//}
		return
	}
	defer realconn.Close()
	log.Println("HTTP Proxy for:", realconn.Rawconn.RemoteAddr())
	realconn.TCP_ECS_Flag = ECS
	realconn.TCP_URG_Flag = URG
	realconn.TCP_Frag_Flag = fregmentFlag
	realconn.TCP_Frag_Len = maxLen
	//log.Println(clientData)
	realconn.WriteData([]byte(clientData))
	TCP.R2T(realconn, clientConn)
	//一次代理请求流程走完,后续还需要考虑一条流中多个会话的问题,请求的目的服务器可能不一致需要修改的.
	wd.Done()
}