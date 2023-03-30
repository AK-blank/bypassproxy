package TCP

import (
	"math/rand"
)

//func errorQueuePacket(conn net.Conn) {
//	errHeader := SYNHeader
//	errHeader.Flags = FIN
//	errHeader.SeqNum = rand.Uint32()
//	errHeader.AckNum = rand.Uint32()
//	errHeader.Payload = []byte("asdasd")
//	errHeader.Checksum = errHeader.tcpCsum32()
//	conn.Write(errHeader.marshal())
//	buf := make([]byte, 100)
//	conn.Read(buf)
//}

/*
可行,但是会被记录重传次数中
最好用在第一次发送数据前,直接干扰解码
能否使用同样的方式干扰IDS对三次握手的检测: SYN->SYN,ACK->Error ACk->Correct ACK
目前可行的组合(所有情况均为错误校验位):
	三次握手完以后发送一个带随机payload的ACK包,可以干扰解码
需要尝试的组合(所有情况均为错误校验位):
	建立完三次握手后发一个RST包,是否会干扰IDS对连接状态的干扰? 这种方式暂时不可行,因为在链接开始前,已经将所有RST包屏蔽了

	分段传输过程中,发送携带干扰数据的流,直接干扰数据重组

*/

func (Conn TcpConn) ErrorCheckSumPacket(flag uint8) {
	errHeader := Conn
	if flag != 0 {
		errHeader.Header.Flags = flag
	}
	errHeader.Header.Payload = randByteData(rand.Intn(1410) + 10)
	errHeader.Header.Checksum = uint16(rand.Uint32())
	errHeader.Rawconn.Write(errHeader.marshal())
}
