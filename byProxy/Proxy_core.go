package byProxy

import (
	"net"
)

//用于区分不同的代理协议,waitGroup sync.WaitGroup
func SuperProxy(clientConn net.Conn, fregmentMaxLen int, fregmentFlag, httpMethodMixing,ECS,URG bool) {
	//如果客户端连接为nil则退出
	if clientConn == nil {
		return
	}
	//defer func(clientConn net.Conn) {
	//	err := clientConn.Close()
	//	if err != nil {
	//
	//	}
	//}(clientConn) //结束时关闭
	//接收客户端数据
	byteclientData := make([]byte,0)
	for {
		cache, err := getMaxData(clientConn)
		if err!= nil{
			return
		}
		if len(cache)!=0{
			byteclientData = append(byteclientData, cache...)
			break
		}

	}
	for i:=0;i<5;i++{
		if string(byteclientData[len(byteclientData)-4:]) != "\r\n\r\n"{
			cache, _ := getMaxData(clientConn)
			byteclientData = append(byteclientData, cache...)
		}else {
			break
		}
	}
	//解析客户端数据
	//开头为CONNECT的话,表示要访问的页面为https协议,否则为http协议
	clientData := string(byteclientData)
	http_Proxy(clientConn, clientData, fregmentMaxLen, fregmentFlag, httpMethodMixing,ECS,URG)
		//if len(clientData) >= 4 && clientData[:1] == string(V5) { //根据长度和标志位判断是否为socks5
		//	socks5_Proxy(clientConn, clientData, fregmentFlag)
		//} else if len(clientData) >= 9 && clientData[:1] == string(V4) { //根据长度和标志位判断是否为socks4
		//	socks4_Proxy(clientConn, clientData, fregmentFlag)
		//} else {
		//	http_Proxy(clientConn, clientData, fregmentMaxLen, fregmentFlag, httpMethodMixing,ECS,URG)
		//}
	//waitGroup.Done()
}
