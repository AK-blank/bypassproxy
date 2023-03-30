package byProxy

import (
	"BypassProxy/byPass"
	"io"
	"net"
	"strings"
)

//该函数用于获取客户端所发出的请求数据,io.Copy可以完美解决这个问题
func getMaxData(conn net.Conn) ([]byte, error) {
	//conn.SetReadDeadline(time.Now().Add(time.Second*1)) //设置0.5秒超时
	//reader := bufio.NewReader(conn)
	var buf [32*1024]byte //64kb大小的缓冲区
	dataLen, err := conn.Read(buf[:]) // 读取数据
	if dataLen != 0 {
		return buf[:dataLen], err
	} else {
		return make([]byte,0),err
	}

	//return "", err
}

//读取tcp标准大小的数据
func getStdData(conn net.Conn) ([]byte, error) {
	//conn.SetReadDeadline(time.Now().Add(time.Second*1)) //设置10秒超时
	var buf [1460]byte
	n, err := conn.Read(buf[:]) // 读取数据
	if n != 0 {
		return buf[0:n], err
	} else {
		return nil, err
	}

}

//接收数据并转发
//存在问题,数据接收不完全就回传数据,导致数据缺失
//现在考虑使用io.Copy代替该功能,保证数据完整性,但是存在一定的问题,就是io.Copy可能会产生无用线程,产生资源占用的问题
func get_Send_Data(recvConn, sendConn net.Conn, fregmentflag bool) error {
	data, err := getMaxData(recvConn)
	if len(data) != 0{
		sendStdData(sendConn, string(data), fregmentflag)
	}
	return err
}

//按照tcp标准大小发送数据
func sendStdData(conn net.Conn, data string, fregflag bool) {
	//flag为false时表示为tcp标准发送,true为分段发送
	if fregflag {
		byPass.Rand_fragment(conn, data, 50)
	} else {
		for {
			dataLen := len(data)
			if dataLen > 1460 {
				_, err := conn.Write([]byte(data[:1460]))
				if err != nil {
					return
				}
				data = data[1460:]
			} else {
				_, err := conn.Write([]byte(data))
				if err != nil {
					return
				}
				break
			}
		}
	}
}

//实现客户端与服务端的流量交互,为get_Send_Data的不分段的优化版本,存在的问题: 数据交互完成后并不会立即断开连接,而是发送keep-alive标志
func tcpCopy(realconn, clientConn net.Conn, fregmengflag bool) error {
	err := make(chan error)
	if fregmengflag {
		go func() {
			_, er := FragCopy(realconn, clientConn, 1)
			if er != nil {
				err <- er
			}
		}()
	} else {
		go func() {
			_, er := io.Copy(realconn, clientConn)
			if er != nil {
				err <- er
			}
		}()
	}
	go func() {
		_, er := io.Copy(clientConn, realconn)
		if er != nil {
			err <- er
		}
	}()
	return <-err
}

//该函数基于io.Copy函数改写,实现完美的分段发送(copy)功能
//适用场景: 点对点的直接数据传输
func FragCopy(dst, src net.Conn, maxLen int) (written int64, err error) {
	// If the reader has a WriteTo method, use it to do the copy.
	// Avoids an allocation and a copy.
	//if wt, ok := src.(io.WriterTo); ok {
	//	return wt.WriteTo(dst)
	//}
	//// Similarly, if the writer has a ReadFrom method, use it to do the copy.
	//if rt, ok := dst.(io.ReaderFrom); ok {
	//	return rt.ReadFrom(src)
	//}
	//上面注释的部分影响了分段传输,后续看看是否要从上面两个逻辑修改分段逻辑

	//实现最极致的分段传输
	buf := make([]byte, maxLen)
	num := 0
	for {
		if maxLen != 1 {
			if num < 3 {
				buf = make([]byte, 1)
				num++
			} else {
				buf = make([]byte, maxLen)
			}
		}

		nr, er := src.Read(buf)
		if nr > 0 {
			nw, ew := dst.Write(buf[0:nr])
			if nw > 0 {
				written += int64(nw)
			}

			if ew != nil {
				err = ew
				break
			}
			if nr != nw {
				err = io.ErrShortWrite
				break
			}
		}
		if er == io.EOF {
			break
		}
		if er != nil {
			err = er
			break
		}
	}
	return written, err
}

//基于FragCopy函数改写,实现将数据发送到目标连接的功能
//用于单向数据分段发送
func FragSend(dst net.Conn, data string, maxLen int) (written int64, err error) {

	src := strings.NewReader(data)
	buf := make([]byte, maxLen)
	//num := 0
	for {
		//if maxLen != 1 {
		//	if num < 3 {
		//		buf = make([]byte, 1)
		//		num++
		//	} else {
		//		buf = make([]byte, maxLen)
		//	}
		//}

		nr, er := src.Read(buf)
		if nr > 0 {
			nw, ew := dst.Write(buf[0:nr])
			if nw > 0 {
				written += int64(nw)
			}

			if ew != nil {
				err = ew
				break
			}
			if nr != nw {
				err = io.ErrShortWrite
				break
			}
		}
		if er == io.EOF {
			break
		}
		if er != nil {
			err = er
			break
		}
	}
	return written, err
}
