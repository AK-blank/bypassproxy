package byProxy

import (
	"log"
	"net"
	"strconv"
	"strings"
)

const (

	// version
	V4 byte = 0x04
	V5 byte = 0x05

	//REQ command
	CONNECT byte = 0x01
	BIND    byte = 0x02
	UDP     byte = 0x03

	//RSP command
	SUC   byte = 0x5a
	REJ   byte = 0x5b
	ERR   byte = 0x5c
	IDERR byte = 0x5d

	//V5 METHODS
	V5NoAuth byte = 0x00
	V5GSSAPI byte = 0x01
	V5PWD    byte = 0x02

	//V5ATYP
	V5ipv4   byte = 0x01 //4bytes
	V5domain byte = 0x03
	V5ipv6   byte = 0x04 //16bytes

)

func socks4_Proxy(clientConn net.Conn, clientData string, fregmentFlag bool) {
	//首先需要判断第二位的命令是什么
	if clientData[1] == CONNECT {
		//获取端口和ip,将字符串类型的十六进制数据转化为对应的10进制数据
		realPort := strconv.Itoa(int(clientData[2])<<8 + int(clientData[3]))
		realHost := net.IPv4(clientData[4], clientData[5], clientData[6], clientData[7])
		//如果长度大于9,说明存在USERID字段,即身份认证功能,此处暂不实现
		//if len(clientData) >9 {
		//	return
		//}
		//创建与真实ip的连接
		realconn, err := net.Dial("tcp", realHost.String()+":"+realPort)
		if err != nil {
			return
		}
		defer func(realConn net.Conn) {
			err := realConn.Close()
			if err != nil {

			}
		}(realconn)
		//向客户端返回连接成功
		rspData := string(V4) + string(SUC) + clientData[2:4] + clientData[4:8]
		sendStdData(clientConn, rspData, false)
		log.Println("socks4 Proxy for:", realconn.RemoteAddr())
		//接收客户端的数据发送给真实ip
		//go io.Copy(realConn,clientConn)

		err = tcpCopy(realconn, clientConn, fregmentFlag)
		if err != nil {
			return
		}

		//clientData,err = getMaxData(clientConn)
		//if err != nil{
		//	return
		//}
		//
		////下面进入协议判断逻辑,可能出现任何基于TCP的应用协议,暂时实现HTTP和TCP分段,不进行协议识别
		//
		//httpFlagReg, _ := regexp.Compile(`^[A-Z]+\x20[\s\S]+?\x20HTTP`)
		////简单判断一下是否为http请求
		//if httpFlagReg.MatchString(clientData){
		//	//log.Println("SOCK4 HTTP代理")
		//	if fregmentFlag {
		//		go byPass.HTTP_fregement(realconn, clientData, maxLen, methodMixing)
		//	} else {
		//		go io.Copy(realconn,clientConn)
		//	}
		//	//将真实ip返回的数据发送给客户端
		//	io.Copy(clientConn,realconn)
		//}else {
		//	//https://www.baidu.com
		//	//log.Println("SOCK4 未知协议代理")
		//	sendStdData(realconn,clientData,fregmentFlag)
		//	go io.Copy(clientConn, realconn)
		//	err := tcpCopy(realconn, clientConn,false)
		//	if err != nil {
		//		return
		//	}
		//}

		//log.Println("i'm in sock4 connect")
	} else if clientData[1:2] == string(BIND) {

	}
}

func socks5_Proxy(clientConn net.Conn, clientData string, fregmentFlag bool) {
	nmethods := clientData[1] //表示METHODS的长度
	methodsLen := int(nmethods)
	methods := clientData[1 : 1+methodsLen]
	//优先使用无认证方式
	if strings.Contains(methods, string(V5NoAuth)) {
		clientConn.Write([]byte("\x05\x00"))
	} else if strings.Contains(methods, string(V5GSSAPI)) { //其次使用GSSAPI方式
		clientConn.Write([]byte("\x05\x01"))
	} else if strings.Contains(methods, string(V5PWD)) { //最后使用用户名密码模式
		clientConn.Write([]byte("\x05\x02"))
	} else {
		return
	}
	//fmt.Println(methods)
	Data, _ := getStdData(clientConn)
	if Data[1] == CONNECT {
		realHost := ""
		realPort := ""
		if Data[3] == V5ipv4 {

		} else if Data[3] == V5domain {
			//获取域名长度
			domainLen := int(Data[4])
			//获取域名和目的端口
			realHost = string(Data[5 : 5+domainLen])
			realPort = strconv.Itoa(int(Data[5+domainLen])<<8 + int(Data[5+domainLen+1]))

			//fmt.Println(realHost)
			//fmt.Println(realPort)
		} else if Data[3] == V5ipv6 {

		} else {
			log.Println("unknown target format")
			return
		}
		if realHost != "" {
			realconn, err := net.Dial("tcp", realHost+":"+realPort)
			if err != nil {
				//log.Println(err)
				return
			}
			cache := make([]byte, 0)
			cache = append(cache, []byte("\x05\x00")...)
			cache = append(cache, Data[2:]...)
			clientConn.Write(cache)
			log.Println("socks5 Proxy for:", realconn.RemoteAddr())
			err = tcpCopy(realconn, clientConn, fregmentFlag)
			if err != nil {
				return
			}
		}

	}
}
