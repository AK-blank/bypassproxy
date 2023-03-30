package TCP

import (
	"errors"
	"net"
)

//等同于net.Dial
func TcpDial(address string) (TSM TcpConn, err error) {

	Dip, DstPort := parseAddress(address)
	if Dip == "" {
		err := errors.New("can't get ip address")
		return TSM, err
	}
	//这一部分可能需要修改
	//_, _ = net.Dial("tcp", Dip)
	conn, err := net.Dial("ip4:tcp", Dip)
	if err != nil {
		return TSM, errors.New("Create raw Socket Error")
	}
	//接上一个注释
	TSM, err = normalHandshakes(conn, DstPort)
	if err != nil {
		return TSM, err
	}
	return TSM, err

}

func CreateTSM(address string) (addrTSM *TcpConn, err error)   {
	dial, err := TcpDial(address)
	if err != nil {
		return nil, err
	}
	return &dial,err
}

func SendByTSM(addrTSM *TcpConn)  {

}