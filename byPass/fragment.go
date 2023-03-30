package byPass

import (
	"math/rand"
	"net"
	"regexp"
	"time"
)

//实现HTTP分段整体逻辑
//参数: 套接字,待传输的数据,最大分片长度
func HTTP_fragement(conn net.Conn, data string, maxLen int, methodMixing bool) {
	rand.Seed(rand.Int63())
	method_reg, _ := regexp.Compile(`^([A-Z]+)`)
	method := method_reg.FindAllString(data, 1)[0]
	//实现请求方式的混淆,但该方法不一定能够成功.
	if methodMixing {
		x := []rune("A")
		for i := 0; i < rand.Intn(10); i++ {
			rand.Seed(rand.Int63())
			randInt := rand.Intn(26) //A-Z最大差值为25,该随机数取值区间为[0,26)
			randAlpha := string(x[0] + rune(randInt))
			if randInt > 13 {
				method = method + randAlpha
			} else {
				method = randAlpha + method
			}
			data = "1" + data //在数据前加一位补充数据,保证数据的偏移正确
		}

	}
	//method := "POST"
	pos := rand.Intn(len(method) - 2)
	_, err := conn.Write([]byte(method[0:pos]))
	if err != nil {
		return
	} //先发送前n位
	Rand_fragment(conn, method[pos:], maxLen) //将请求方法继续分段发送
	Rand_fragment(conn, data[len(method):], maxLen)
	//var recvData = make([]byte, 65535) //接收缓冲区 默认大小65535
	//if _, err := conn.Read(recvData); err != nil{
	//	fmt.Printf("Read failed , err : %v\n", err)
	//}
	//return string(recvData)
}

//实现分段的核心逻辑
//参数: 套接字,待传输的数据,最大分片长度
func Rand_fragment(conn net.Conn, data string, maxLen int) {
	i := 0
	data_len := len(data)
	for {
		rand.Seed(rand.Int63())
		if (data_len - i) > 1 {
			randomint := rand.Intn(data_len - i)
			//限制分块的最大长度
			if randomint != 0 && randomint < maxLen {
				_, err := conn.Write([]byte(data[i : i+randomint]))
				if err != nil {
					return
				}
				time.Sleep(time.Duration(rand.Intn(10)) * time.Millisecond)
				i += randomint
			}
			if data == "" {
				break
			}
		} else {
			_, err := conn.Write([]byte(data[i:]))
			if err != nil {
				return
			}
			break
		}

	}
}
