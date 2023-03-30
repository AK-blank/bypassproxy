package TCP

import (
	"errors"
	"log"
	"net"
	"sync"
	"time"
)

/*
是否需要像TCP协议标准实现中所说,维护一个全局变量表,以便于判断当前的状态
*/

const (
	LISTEN       = 0x00
	SYN_SENT     = 0x01 //发送SYN包时,使用该标志位
	SYN_RECEIVED = 0x02 //接收到SYN,ACK时,使用该标志位
	ESTABLISHED  = 0x03 //三次握手结束后使用该标志位
	FIN_WAIT_1   = 0x04
	FIN_WAIT_2   = 0x05
	CLOSE_WAIT   = 0x06
	CLOSING      = 0x07
	LAST_ACK     = 0x08
	TIME_WAIT    = 0x09
	CLOSED       = 0x0a
)

type TcpConn struct {
	Rawconn         net.Conn
	Header          tcpHeader
	TCP_recv_flag   byte   //上次接收的Flag
	TCP_recv_Seq    uint32 //上次接收的seqnum
	TCP_recv_Ack    uint32 //上次接收的acknum
	TCP_recv_Retime	int	//重读数据的次数
	//TCP_recv_ExpLen int    // 接收数据的预期长度
	//TCP_recv_LastPayloadLen int
	MaxSeg            uint16 //最大payload
	TCP_Tspot_flag    int    //时间戳选项是否开启
	Tsval             uint32
	Tsecr             uint32
	TCP_State         byte //TCP连接的当前状态
	TCP_send_LastFlag bool //表示本次发送是否为最后一次
	//TCP_send_Sent	  bool
	TCP_URG_Flag      bool //URG标志位是否开启
	TCP_ECS_Flag      bool //错误校验码
	TCP_Frag_Flag	  bool
	TCP_Frag_Len	  int
	//Misc_iptable	  bool //iptables 设置是否成功


}

func normalHandshakes(conn net.Conn, DstPort uint16) (TSM TcpConn, err error) {

	TSM = TcpConn{
		Rawconn: conn,
	}

	//初始化协议头
	//SYNHeader.syninit(DstPort)
	TSM.syninit(DstPort)

	//创建TCP头以后,添加iptables的规则限制,发包前添加规则,整个函数函数交互结束后删除规则
	//ruleAdd := fmt.Sprintf("iptables -t filter -I OUTPUT -p tcp -s %s --sport %d -d %s --dport %d  --tcp-flags RST RST -j DROP", conn.LocalAddr().String(), TSM.Header.SrcPort, conn.RemoteAddr().String(), TSM.Header.DstPort)

	//生成校验和checksum,注意事项,每次生成数据前,必须重新生成校验和
	//SYNHeader.Checksum = SYNHeader.tcpCsum32()
	//发送三次握手的第一次,即SYN包
	//TSM.Misc_iptable = true
	_, err = conn.Write(TSM.genData())
	if err != nil {
		return TSM, err
	}
	TSM.TCP_State = SYN_SENT
	//SYNHeader.Payload = make([]byte,0)
	//TCP_send_Seq = SYNHeader.SeqNum
	//TCP_send_Ack = SYNHeader.AckNum

	//接收ACK,即第二次握手
	buf := make([]byte, 60)
	n, err := conn.Read(buf)
	if err != nil {
		return TSM, err
	}
	_, err = TSM.parseTcpRsp(buf[:n])
	if TSM.TCP_recv_flag != SYN+ACK {
		err = errors.New("Flags don't equal SYN+ACK") //这里总会报错
		return TSM, err
	}
	if err != nil {
		return TSM, err
	}
	if TSM.Tsecr != 0 {
		TSM.TCP_Tspot_flag = 1
	}
	TSM.sendAck(0)
	//log.Println("三次握手结束后,此时的TCP标志位:",TSM.Header.Flags)
	return TSM, err

}

func (Conn *TcpConn) sendAck(payloadLen uint32) {

	if Conn.TCP_recv_flag == SYN+ACK && Conn.TCP_State == SYN_SENT {
		//log.Println("进入YN+ACK的sendACK")
		Conn.TCP_State = SYN_RECEIVED
		Conn.Header.SeqNum = Conn.TCP_recv_Ack
		Conn.Header.AckNum = Conn.TCP_recv_Seq + 1
		Conn.Header.Flags = ACK
		if Conn.TCP_Tspot_flag == 1 {
			Conn.Header.Options = updateTspot(Conn.Tsval, Conn.Tsecr)
			Conn.Header.fillNOP()
		} else {
			Conn.Header.Options = make([]byte, 0)
		}
		//不携带pyload时,需要将payload字段清零,目前在发送完数据后已经清零
		//SYNHeader.Payload = make([]byte,0)
		Conn.Header.Len = Conn.updateHeaderLen()
		//SYNHeader.Checksum = SYNHeader.tcpCsum32()
		//发送第三次握手,成功建立连接
		Conn.Rawconn.Write(Conn.genData())
		//发完包需要更新全局变量
		Conn.TCP_State = ESTABLISHED
		//TCP_send_Seq = SYNHeader.SeqNum
		//TCP_send_Ack = SYNHeader.AckNum
	} else if ((Conn.TCP_recv_flag == PSH+ACK||Conn.TCP_recv_flag == ACK) && Conn.TCP_State == ESTABLISHED) || Conn.TCP_State == FIN_WAIT_2 {
		//log.Println("进入PSH+ACK的sendACK,此时payload长度:",payloadLen)
		Conn.Header.SeqNum = Conn.TCP_recv_Ack
		if payloadLen != 0 {
			Conn.Header.AckNum = Conn.TCP_recv_Seq + payloadLen //存在数据的话需要加payload的长度,否则+1
		} else {
			Conn.Header.AckNum = Conn.TCP_recv_Seq + 1
		}
		Conn.Header.Flags = ACK
		if Conn.TCP_Tspot_flag == 1 {
			Conn.Header.Options = updateTspot(Conn.Tsval, Conn.Tsecr)
			Conn.Header.fillNOP()
			Conn.Header.Len = Conn.updateHeaderLen()
		}
		//SYNHeader.Checksum = SYNHeader.tcpCsum32()
		Conn.Rawconn.Write(Conn.genData())

	} else if Conn.TCP_State == CLOSING {
		Conn.Header.SeqNum = Conn.TCP_recv_Ack
		Conn.Header.AckNum = Conn.TCP_recv_Seq
		Conn.Header.Flags = FIN + ACK
		if Conn.TCP_Tspot_flag == 1 {
			Conn.Header.Options = updateTspot(Conn.Tsval, Conn.Tsecr)
			Conn.Header.fillNOP()
			Conn.Header.Len = Conn.updateHeaderLen()
		}
		//SYNHeader.Checksum = SYNHeader.tcpCsum32()
		Conn.Rawconn.Write(Conn.genData())

		Conn.Header.SeqNum++
		Conn.Header.Flags =ACK
		if Conn.TCP_Tspot_flag == 1 {
			Conn.Header.Options = updateTspot(Conn.Tsval, Conn.Tsecr)
			Conn.Header.fillNOP()
			Conn.Header.Len = Conn.updateHeaderLen()
		}
		//SYNHeader.Checksum = SYNHeader.tcpCsum32()
		Conn.Rawconn.Write(Conn.genData())

		Conn.TCP_State = CLOSED
	}
}

/*
//完整数据分段发送的时候seqNum需要增加,AckNum不变
//发送payload,无需关注TCP头的组成
还需要实现:
	任意分段传输
	URG传输
	混入错误校验和
*/
//
func (Conn *TcpConn) WriteData(payload []byte) (write int, err error) {
	var memoryAccess sync.Mutex
	memoryAccess.Lock()
	defer memoryAccess.Unlock()
	//log.Println("发送数据前的flag是:",Conn.TCP_recv_flag,len(payload))

	if Conn.TCP_State != ESTABLISHED {
		err = errors.New("TCP Don't Establish,Current State:" + string(rune(Conn.TCP_State)))
		return 0, err
	}
	Conn.Header.Payload = make([]byte,0)
	maxPayloadLen := (int(Conn.MaxSeg) + 54) - 14 - 20 - len(Conn.marshal())
	currentPayloadLen := len(payload)
	if currentPayloadLen == 0{
		log.Println("最大payload长度为:",maxPayloadLen,",最大段长度为:",Conn.MaxSeg,",当前头长度为:",len(Conn.marshal()))
		return write,err
	}
	//当数据长度小于当前可承载的最大长度时,可以一次发送完毕

	//存在URG标志位时添加URG
	if Conn.TCP_URG_Flag {
		Conn.Header.Flags = PSH + ACK + URG
		Conn.Header.Urg = uint16(1)
	} else {
		Conn.Header.Flags = PSH + ACK
	}

	if currentPayloadLen <= maxPayloadLen {
		//Conn.Rawconn.SetWriteDeadline(time.Now().Add(Conn.Misc_timeline))
		//不分段发送请求
		//这种情况是建立连接以后的第一次请求,不需要修改序列号,以及时间戳选项
		if Conn.TCP_recv_flag == SYN+ACK {
			//log.Println("进入SYN+ACK响应阶段")
			Conn.Header.Len = uint8(len(Conn.marshal())) << 2
			if Conn.TCP_URG_Flag {
				Conn.Header.Payload = make([]byte, 0)
				Conn.Header.Payload = append(Conn.Header.Payload, randByteData(1)...)
				Conn.Header.Payload = append(Conn.Header.Payload, payload...)
			} else {
				Conn.Header.Payload = payload
			}

			if Conn.TCP_ECS_Flag {
				Conn.ErrorCheckSumPacket(Conn.Header.Flags)
			}

			write, err = Conn.Rawconn.Write(Conn.genData())
			Conn.Header.Payload = make([]byte, 0) // 发完数据包需要将payload部分恢复初始状态
			if err != nil {
				log.Println("1发送错误",err)
				return write, err
			}
			return write, err
		} else if Conn.TCP_recv_flag == ACK || Conn.TCP_recv_flag == ACK+PSH {
			//log.Println("进入PSH+ACK响应阶段")
			//log.Println("进入多数据交互逻辑")
			//这种是多数据交互情况下,需要修改序列号以及时间戳选项,不需要修改headerLen
			if Conn.TCP_URG_Flag {
				Conn.Header.Payload = make([]byte, 0)
				Conn.Header.Payload = append(Conn.Header.Payload, randByteData(1)...)
				Conn.Header.Payload = append(Conn.Header.Payload, payload...)
			} else {
				Conn.Header.Payload = payload
			}
			if Conn.TCP_ECS_Flag {
				Conn.ErrorCheckSumPacket(Conn.Header.Flags)
			}
			write, err = Conn.Rawconn.Write(Conn.genData())
			Conn.Header.Payload = make([]byte, 0) // 发完数据包需要将payload部分恢复初始状态
			if err != nil {
				log.Println("2发送错误",err)
				return write, err
			}
			if Conn.TCP_send_LastFlag == false {
				Conn.readAck()
			}
			return write, err
		}
	} else {
		//log.Println("进入分段传输")
		//log.Println(string(payload))
		currentPos := 0
		wholeTimes := currentPayloadLen / maxPayloadLen
		for i := 0; i < wholeTimes; i++ {
			err = Conn.FragWrite(payload, maxPayloadLen)
			if err != nil {
				return 0, errors.New("分段写入错误")
			}
			currentPos += maxPayloadLen
		}
		_, err = Conn.WriteData(payload[currentPos:])
		if err != nil {
			return 0, errors.New("分段最后一次写入错误")
		}

	}
	return 0, err
}

//
//
////分段发送数据,目前建议最小值为4
func (Conn *TcpConn) FragWrite(payload []byte, maxLen int) (err error) {
	payloadLen := len(payload)
	if maxLen > payloadLen {
		err = errors.New("maxLen more than length of payload")
		return err
	}
	//log.Println("总数据",payloadLen)
	for i := 0; i < payloadLen; i += maxLen {
		if i+maxLen < payloadLen {
			Conn.Rawconn.SetWriteDeadline(time.Now().Add(time.Second))
			//log.Println("分段发送",i)
			_, err = Conn.WriteData(payload[i : i+maxLen])
			if err != nil {
				//log.Println("发送错误",err)
				return err
			}
			//if i ==0 {
			//	err = Conn.readAck()
			//	if err != nil {
			//		return err
			//	}
			//}
			if Conn.TCP_recv_flag == SYN+ACK {
				err = Conn.readAck()
				if err != nil {
					log.Println("读取错误",err)
					return err
				}
			}
			var memoryAccess sync.Mutex
			memoryAccess.Lock()
			Conn.TCP_recv_flag = PSH + ACK
			Conn.Header.SeqNum = Conn.TCP_recv_Ack
			Conn.Header.AckNum = Conn.TCP_recv_Seq
			memoryAccess.Unlock()
			//}

		} else {
			//log.Println("最后一次发送",i)
			var memoryAccess sync.Mutex
			memoryAccess.Lock()
			Conn.TCP_send_LastFlag = true
			memoryAccess.Unlock()
			_, err = Conn.WriteData(payload[i:])
			if err != nil {
				return err
			}
		}

	}
	return err
}

//接收payload,无需关注TCP头的组成
func (Conn *TcpConn) ReadData() (payload []byte, err error) {
	//Conn.Rawconn.SetReadDeadline(time.UnixMilli(0))
	//Conn.Rawconn.SetReadDeadline(time.Now().Add(1 * time.Second))
	if Conn.TCP_State != ESTABLISHED{
		return payload,errors.New("ReadData 连接状态不等于ESTABLISHED")
	}
	//系统底层是如何实现网络协议的
	//先设置一个1M的缓冲区,1024个连接就是1G的缓冲区了
	buf := make([]byte, 1024*1024) //缓冲区设置的小一点可以回复ACK,否则对端可能以为数据没有发送成功
	defer func() {
		buf = make([]byte,0)
	}()
	n, err := Conn.Rawconn.Read(buf) //这地方总卡住
	if err != nil {
		return nil, err
	}
	payload, err = Conn.parseTcpRsp(buf[:n])

	if err != nil {
		return nil, err
	}
	if Conn.Tsval != 0 && Conn.Tsecr != 0 {
		Conn.TCP_Tspot_flag = 1
	} else {
		Conn.TCP_Tspot_flag = 0
	}
	if Conn.TCP_recv_flag == RST || Conn.TCP_recv_flag == RST+ACK {
		return payload, errors.New("Receive RST")
	}


	//读完以后需要回复ACK包,表示已收到该数据包


	if len(payload) == 0 && Conn.TCP_recv_Retime <10{
		Conn.TCP_recv_Retime ++
		return Conn.ReadData()
	} else {
		Conn.TCP_recv_Retime = 0
		//log.Println("已接收到数据:",len(payload),",准备发送ACK")
		Conn.sendAck(uint32(len(payload)))
		Conn.TCP_send_LastFlag = false //读取完数据要将相关标志位恢复默认
		return payload, err
	}

}

//
//
//
//
//用于读取分段传输时服务端返回的ACK,并解析响应,更新状态
func (Conn *TcpConn) readAck() error {
	//Conn.Rawconn.SetReadDeadline(time.Now().Add(time.Second))
	buf := make([]byte, 60)
	n, err := Conn.Rawconn.Read(buf)
	if err != nil {
		return err
	}
	_, err = Conn.parseTcpRsp(buf[:n])
	if Conn.TCP_recv_flag == ACK {
		return err
	} else if Conn.TCP_recv_flag == ACK+RST {
		return errors.New("Receive RST")
	}
	return err
}




func (Conn *TcpConn)Close()  {
	defer func() {
		err := Conn.Rawconn.Close()
		if err != nil {
			log.Println(err)
			return
		}
	}()
	err := Conn.readAck()
	if err != nil {
	}
	Conn.Header.SeqNum = Conn.TCP_recv_Ack
	Conn.Header.AckNum = Conn.TCP_recv_Seq
	Conn.Header.Flags = FIN+ACK
	if Conn.TCP_Tspot_flag == 1 {
		Conn.Header.Options = updateTspot(Conn.Tsval, Conn.Tsecr+1)
		Conn.Header.fillNOP()
	}

	_, err = Conn.Rawconn.Write(Conn.genData())
	if err != nil {
		//log.Println(err)
		return
	}
	Conn.Header.SeqNum++
	Conn.Header.Flags = ACK
	_, err = Conn.Rawconn.Write(Conn.genData())
	if err != nil {
		//log.Println(err)
		return
	}


	//Conn.ReadData()
	//log.Println("关闭信息发送完毕")
}

func R2T(rawConn TcpConn, conn net.Conn) {
	var wd sync.WaitGroup
	for{
		data, err := rawConn.ReadData()
		if len(data)==0 || err != nil{
			return
		}
		wd.Add(1)
		go func() {
			_, err = conn.Write(data)
			if err != nil {
				return
			}
			wd.Done()
		}()
		wd.Wait()
	}
}


func getMaxData(conn net.Conn) ([]byte, error) {
	//conn.SetReadDeadline(time.Now().Add(time.Second*1)) //设置0.5秒超时
	//reader := bufio.NewReader(conn)
	var buf [32*1024]byte //32kb大小的缓冲区
	dataLen, err := conn.Read(buf[:]) // 读取数据
	if dataLen != 0 {
		return buf[:dataLen], err
	} else {
		return make([]byte,0),err
	}

	//return "", err
}


//rawconn和net.conn之间的交互转发
func (Conn *TcpConn)RawCopy(clientConn net.Conn)  {
	//clientConn.SetDeadline(time.Now().Add(time.Second*5))
	//Conn.Rawconn.SetDeadline(time.Now().Add(time.Second*10))
	//var memoryAccess sync.Mutex
	sentFlag := make(chan int,1) //用于控制第二个协程是否开始
	receiveFlag := make(chan int,1) //用于控制第一个协程是否开始
	allDone := make(chan int,2)
	receiveFlag <- 1

	defer func() {
		close(allDone)
		close(sentFlag)
		close(receiveFlag)
		clientConn.Close()
		//log.Println("代理结束啦!")
	}()

	var wd sync.WaitGroup
	//log.Println("数据交互前的标志位:",realconn.Header.Flags)
	wd.Add(1)
	go func() {
		defer func() {
			//
			//memoryAccess.Lock()
			if Conn.TCP_State != CLOSE_WAIT{
				Conn.TCP_State = CLOSE_WAIT
				Conn.Close()
			}
			//memoryAccess.Unlock()
			allDone<-1
			//log.Println("goroutine1结束")
			wd.Done()
		}()
		for {
			select {
			case <-receiveFlag:
				//log.Println("接收一次")
				//<-receiveFlag
				//将客户端数据写入缓冲区
				data, err := getMaxData(clientConn) //这里是阻塞的
				if err != nil {
					return
				}
				//if len(data) == 0{
				//	continue
				//}
				//将缓冲区数据写入服务端
				if Conn.TCP_Frag_Flag{
					err = Conn.FragWrite(data, Conn.TCP_Frag_Len)
				}else {
					_, err = Conn.WriteData(data)
				}
				if err != nil {

					return
				}
				sentFlag <- 1
			case <-time.After(time.Second*20):
				return
			case <-allDone:
				return
			}


		}
	}()

	wd.Add(1)
	go func() {
		defer func() {
			//log.Println("goroutine2结束")
			//memoryAccess.Lock()
			if Conn.TCP_State != CLOSE_WAIT{
				Conn.TCP_State = CLOSE_WAIT
				Conn.Close()
			}
			//memoryAccess.Unlock()
			allDone<-1
			wd.Done()
		}()
		for{
			select {
			case <-sentFlag :
				//log.Println("进入sentFlag")
				//问题1:数据发送完毕后没有及时的返回ACK
				//问题2:一次性没有接受完所有数据, 目前使用循环多次接收
				//data := make([]byte,0)
				for{
					Conn.Rawconn.SetReadDeadline(time.Now().Add(time.Second*1))
					cache, err := Conn.ReadData()
					if len(cache) == 0 {
						break
					}else if err != nil{
						return
					}else {
						//data = append(data, cache...)
						_, err = clientConn.Write(cache)
						if err != nil {
							return
						}
					}
				}
				receiveFlag<-1
			case <-time.After(time.Second*20):
				return
			case <-allDone:
				return
			}
		}
	}()
	wd.Wait()
}
