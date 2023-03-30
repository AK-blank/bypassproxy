package TCP

import (
	"encoding/binary"
	"log"
	"math/rand"
)

//数据转换函数
//uint16转[]byte
func uint16toBytes(intdata uint16) (data []byte) {
	return append(data, byte(intdata>>8), byte(intdata&0xFF))
}

//uint32转[]byte
func uint32toBytes(intdata uint32) (data []byte) {
	return append(data, byte(intdata>>24), byte(intdata>>16), byte(intdata>>8), byte(intdata&0xFF))
}

//[]byte转uint16,默认情况只适用于两位,如果大于2且是2的倍数,则循环调用相加,用于校验和的计算
func bytestoUint16(buf []byte) uint16 {
	rst := uint16(0)
	if len(buf) == 2 {
		rst = binary.BigEndian.Uint16(buf)
		return rst
	} else if len(buf)%2 == 0 {
		for i := 0; i < len(buf); i += 2 {
			rst += binary.BigEndian.Uint16(buf[i : i+2])
		}
		return rst
	} else {
		log.Println("not support this format:", buf)
		return 0
	}
}

//[]byte转uint32,默认情况只适用
func bytestoUint32(buf []byte) uint32 {
	rst := uint32(0)
	if len(buf) == 0 {
		return 0
	} else {
		if len(buf) == 4 {
			rst = binary.BigEndian.Uint32(buf)
			return rst
		} else if len(buf)%4 == 0 {
			for i := 0; i < len(buf); i += 4 {
				rst += binary.BigEndian.Uint32(buf[i : i+4])
			}
			return rst
		} else {
			cache := 4 - len(buf)%4
			fillBytes := make([]byte, cache)
			buf = append(buf, fillBytes[:]...)
			for i := 0; i < len(buf); i += 4 {
				rst += binary.BigEndian.Uint32(buf[i : i+4])
			}
			return rst
		}
	}

}

func randByteData(n int) []byte {
	if n == 0 {
		return make([]byte, 0)
	}
	b := make([]byte, n)
	for i := 0; i < len(b); i++ {
		b[i] = byte(rand.Intn(256))
	}
	return b
}
