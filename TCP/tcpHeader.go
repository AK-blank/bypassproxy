package TCP

import (
	"errors"
	"log"
	"math/rand"
	"net"
	"strconv"
	"strings"
	"time"
)

//TCPHeader test
type tcpHeader struct {
	SrcPort  uint16
	DstPort  uint16
	SeqNum   uint32
	AckNum   uint32 //第一次为0,后续根据ACK更新
	Len      uint8
	Flags    uint8
	Window   uint16 //这个参数是什么意思
	Checksum uint16
	Urg      uint16 //通常为0,URG标志位为1时开始设置
	Options  []byte
	Payload  []byte
}

const (
	URG = 0x20
	ACK = 0x10
	PSH = 0x08
	RST = 0x04
	SYN = 0x02
	FIN = 0x01
)

//SYN包结构体基本元素初始化
func (Conn *TcpConn) syninit(DstPort uint16) {
	//TCP协议头初始化
	Conn.Header.SrcPort = getSrcPort()
	Conn.Header.DstPort = DstPort
	//使用系统时间戳生成随机数种子
	rand.Seed(time.Now().Unix())
	////a := uint32(3651179895)
	Conn.Header.SeqNum = rand.Uint32()
	Conn.Header.Window = 65535
	Conn.Header.Flags = SYN
	//添加TCP选项:Options
	/*
		时间戳
		SACK
		MAX
		NOP
		window scale
	*/
	//设置WSS=1460
	Conn.Header.Options = append(Conn.Header.Options, getWSS(1460)...)
	Conn.Header.Options = append(Conn.Header.Options, getSACK()...)
	Conn.Header.Options = append(Conn.Header.Options, getTspot()...)
	Conn.Header.Options = append(Conn.Header.Options, getWspot()...)
	Conn.Header.fillNOP()
	//修正数据长度
	Conn.Header.Len = Conn.updateHeaderLen() //左移两位,将数据长度对齐
}

func (Conn *TcpConn) genData() (data []byte) {
	Conn.Header.Checksum = Conn.tcpCsum32()
	return Conn.marshal()
}

//将tcpHeader的数据转化为byte类型
func (Conn TcpConn) marshal() (data []byte) {
	//按顺序添加相关数据
	//uint16转byte
	data = append(data, uint16toBytes(Conn.Header.SrcPort)[:]...)
	data = append(data, uint16toBytes(Conn.Header.DstPort)[:]...)
	//uint32转byte
	data = append(data, uint32toBytes(Conn.Header.SeqNum)[:]...)
	data = append(data, uint32toBytes(Conn.Header.AckNum)[:]...)
	//uint8不需要转
	data = append(data, Conn.Header.Len)
	data = append(data, Conn.Header.Flags)

	data = append(data, uint16toBytes(Conn.Header.Window)[:]...)
	data = append(data, uint16toBytes(Conn.Header.Checksum)[:]...)
	data = append(data, uint16toBytes(Conn.Header.Urg)[:]...)
	if Conn.Header.Options != nil {
		data = append(data, Conn.Header.Options[:]...)
	}

	if Conn.Header.Payload != nil {
		data = append(data, Conn.Header.Payload[:]...)
	}
	return data
}

//参考连接:https://stackoverflow.com/questions/66142461/tcp-calculate-checksum#comment127123952_66161909
//结合网上找到的checksum函数,实现tcp checksum的计算
func (Conn TcpConn) tcpCsum32() uint16 {
	//首先需要自己先生成一个伪IP协议头
	sipByte := make([]byte, 0)
	for _, ipStr := range strings.Split(Conn.Rawconn.LocalAddr().String(), ".") { //得到string类型
		ipInt, _ := strconv.Atoi(ipStr)
		sipByte = append(sipByte, byte(ipInt))
	}
	//fmt.Println(sipByte)

	dipByte := make([]byte, 0)
	for _, ipStr := range strings.Split(Conn.Rawconn.RemoteAddr().String(), ".") { //得到string类型
		ipInt, _ := strconv.Atoi(ipStr)
		dipByte = append(dipByte, byte(ipInt))
	}

	//根据checksum原理重新组为[]byte
	buf := make([]byte, 0)
	buf = append(buf, sipByte...) //添加源目的ip
	buf = append(buf, dipByte...)
	buf = append(buf, byte(0x00), byte(0x06)) //添加tcp协议标志
	payloadLen := len(Conn.Header.Payload)
	buf = append(buf, uint16toBytes(uint16(Conn.Header.Len>>2)+uint16(payloadLen))...) //添加TCP头部长度和payload长度的校验和
	//以上是伪IP协议头的全部构成
	//fmt.Println(uint32toBytes(uint32(header.Len>>2) + uint32(payloadLen)))
	buf = append(buf, uint16toBytes(Conn.Header.SrcPort)...) //添加源目port
	buf = append(buf, uint16toBytes(Conn.Header.DstPort)...)
	buf = append(buf, uint32toBytes(Conn.Header.SeqNum)...) //添加seq和ack值
	buf = append(buf, uint32toBytes(Conn.Header.AckNum)...)
	buf = append(buf, Conn.Header.Len, Conn.Header.Flags)   //添加长度和Flags
	buf = append(buf, uint16toBytes(Conn.Header.Window)...) //添加window
	buf = append(buf, byte(0x00), byte(0x00))               //添加一个空的checksum
	buf = append(buf, uint16toBytes(Conn.Header.Urg)...)    //添加urg
	if Conn.Header.Options != nil {                         //Add TCP options
		buf = append(buf, Conn.Header.Options...)
	}
	if payloadLen > 0 { //Add TCP payload
		cache := Conn.Header.Payload
		if payloadLen%2 != 0 {
			cache = append(cache, byte(0))
		}
		buf = append(buf, cache...)
	}

	return Checksum(buf, uint32(len(buf)))

}

//参考网上实现的checksum
func Checksum(buffer []byte, size uint32) uint16 {

	var checksum uint32
	for i := 0; size > 0; i += 2 {
		checksum += uint32(buffer[i]) + uint32(buffer[i+1])<<8
		size -= 2
	}
	checksum = checksum>>16 + (checksum & 0xffff)
	checksum += checksum >> 16

	//获取checksum,但是得到的结果由于大小端不对齐的问题,需要转换一下
	cache1 := uint16(checksum ^ 0xffff)
	cache2 := make([]byte, 0)
	cache2 = append(cache2, uint16toBytes(cache1)[1], uint16toBytes(cache1)[0])
	return bytestoUint16(cache2)

	//return
}

func CheckSum_better(data []byte) uint16 {
	var (
		sum    uint32
		length int = len(data)
		index  int
	)
	for length > 1 {
		sum += uint32(data[index])<<8 + uint32(data[index+1])
		index += 2
		length -= 2
	}
	if length > 0 {
		sum += uint32(data[index])
	}
	sum += (sum >> 16)

	return uint16(^sum)
}


//本地获取一个空闲端口
func getSrcPort() uint16 {
	addr, _ := net.ResolveTCPAddr("tcp", "localhost:0")
	l, _ := net.ListenTCP("tcp", addr)
	defer l.Close()
	return uint16(l.Addr().(*net.TCPAddr).Port)
}

//从地址中获取远程ip和远程端口
func parseAddress(address string) (string, uint16) {
	index := strings.Index(address, ":")
	if index == -1 || index == len(address) {
		log.Println("unknown DstPort!")
		return "", 0
	}
	port, _ := strconv.ParseUint(address[index+1:], 10, 64)
	return address[:index], uint16(port)
}


//TCP响应的组成:伪IP头+TCP头+Payload
//解析TCP响应,判断序列号是否正确,解析TCP OPTIONS
func (Conn *TcpConn) parseTcpRsp(buf []byte) (payload []byte, err error) {
	if len(buf) == 0 {
		err = errors.New("Rsp buf data null!")
		return payload, err
	}
	//首先需要先获取ip头的长度,再获取总长度,根据该长度判断tcp协议头的起始位置
	ipheaderLen := buf[0] << 2
	if len(buf) < (int(ipheaderLen) + 20) {
		err = errors.New("Rsp buf data error!")
		return payload, err
	}
	//log.Println("本次接收ip头的长度为:",ipheaderLen)
	totalLen := bytestoUint16(buf[2:4])
	//log.Println("本次接收tcp+payload的总长度为:",totalLen)
	Conn.TCP_recv_Seq = bytestoUint32(buf[ipheaderLen+4 : ipheaderLen+8])
	Conn.TCP_recv_Ack = bytestoUint32(buf[ipheaderLen+8 : ipheaderLen+12])

	//(((header.AckNum == 0) && header.AckNum < TCP_recv_Seq) || header.AckNum == TCP_recv_Seq) && header.SeqNum < TCP_recv_Ack
	//判断序列号是否正确,是否需要考虑返回错误校验和的情况,系统是否会帮忙过滤?
	if (
		((Conn.Header.AckNum == 0) && Conn.Header.AckNum < Conn.TCP_recv_Seq) || Conn.Header.AckNum == Conn.TCP_recv_Seq) &&
		Conn.Header.SeqNum <= Conn.TCP_recv_Ack {
		tcpheaderLen := buf[ipheaderLen+12] >> 2
		Conn.TCP_recv_flag = buf[ipheaderLen+13]
		if Conn.TCP_recv_flag == FIN+ACK || Conn.TCP_recv_flag == FIN+ACK+PSH {
			//直接发送结束
			Conn.TCP_State = CLOSING
			Conn.sendAck(0)
		}
		//获取Options,
		Options := buf[ipheaderLen+20 : ipheaderLen+tcpheaderLen]

		for i := 0; i < len(Options); i += 2 {
			if bytestoUint16(Options[i:i+2]) == 516 && len(Options)-i >= 4 {
				Conn.MaxSeg = bytestoUint16(Options[i+2 : i+4])
				continue
			}

			//解析时间戳
			if bytestoUint16(Options[i:i+2]) == 2058 && len(Options)-i >= 10 {
				Conn.Tsval = bytestoUint32(Options[i+2 : i+6])
				Conn.Tsecr = bytestoUint32(Options[i+6 : i+10])
				continue
			}
		}

		//这一部分考虑返回数据的指针,这样就可以减少数据的复制
		//fmt.Println(Options)
		payload = make([]byte, 0)
		if uint16(tcpheaderLen)+uint16(ipheaderLen) != totalLen {
			//log.Println("payload总长度为:",totalLen-(uint16(tcpheaderLen)+uint16(ipheaderLen)))
			//进入有payload逻辑
			payload = append(payload, buf[ipheaderLen+tcpheaderLen:]...)
		}
		return payload, nil
	} else {
	//	err = errors.New("sequence error!")
	//	return payload, err
	}
	return payload, nil

}

func (Conn TcpConn) updateHeaderLen() uint8 {
	return uint8(len(Conn.marshal())) << 2
}

/*
构造TCP Options等
*/

//构造WSS
func getWSS(size uint16) []byte {

	buf := make([]byte, 0)
	buf = append(buf, 0x02, 0x04) //标志位: Kind & Length
	buf = append(buf, uint16toBytes(size)[:]...)
	return buf

}

//填充NOP,
func (header *tcpHeader) fillNOP() {
	size := len(header.Options)
	residue := size % 4
	if residue != 0 {
		bufNOP := make([]byte, 0)
		bufNOP = append(bufNOP, 0x01, 0x01, 0x01)
		header.Options = append(header.Options, bufNOP[:residue]...)
	}

}

/*
时间戳是单调递增的,但不与实际时间挂钩
RFC1323中推荐每次将时间戳+1
响应方将接收到的TSval原封不动的填充到TSecr
类似于seqNum和ackNum一样,每次交互调换位置即可
PAWS攻击,防绕回序列号
*/
//构造时间戳
func getTspot() []byte {
	buf := make([]byte, 0)
	buf = append(buf, 0x08, 0x0a) //标志位: Kind & Length
	//buf = append(buf)
	buf = append(buf, uint32toBytes(rand.Uint32())...) //TSval,作为发送端时随机生成
	buf = append(buf, uint32toBytes(0)...)             //TSecr
	return buf
}

func updateTspot(Tsval, Tsecr uint32) []byte {
	buf := make([]byte, 0)
	buf = append(buf, 0x08, 0x0a)
	buf = append(buf, uint32toBytes(Tsecr+1)...) //将接收到的Tsecr至少+1作为Tsval送回去
	buf = append(buf, uint32toBytes(Tsval)...)   //将接收到的Tsval原封不动的作为Tsecr送回去
	return buf

}

//获取SACK
func getSACK() []byte {
	buf := make([]byte, 0)
	buf = append(buf, 0x04, 0x02) //标志位: Kind & Length
	return buf
}

//构造windowscale
func getWspot() []byte {
	buf := make([]byte, 0)
	buf = append(buf, 0x01, 0x03, 0x03, 0x07) //标志位: Kind & Length
	return buf
}
