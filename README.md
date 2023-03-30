## ����ģ��
Ŀǰʵ�ֵĴ���:

1. HTTP
2. socks4
3. socks5

## �ƹ�����

1. HTTP����:HTTP/s������Ƭ
2. socks����:ȫ������Ƭ

## ˼ά�籩

- [x] TCPӦ�ò��ƹ����ݴ���ֶ�
- [ ] ͨ��RAW socketʵ��TCP��
- [ ] ͨ��RAW socketʵ��IP��(�ɱ�̫��,��Ч����һ����,��ʱ����)

���·�����Ҫ�Լ�ʵ��RAW Socket

- [ ] IP��Ƭ(�ɱ�̫��,��Ч����һ����,��ʱ����)



- [ ] �������KEEP-Alive

```
ԭ��:
	��������ʱ��ԭ������
```



- [ ] ������ʱ��

```
ԭ��:
	IDS/IPS��������Զ�ȴ�,ֻҪ��ʱ�����ܹ���֤�������ȴ��IDS/IPS�ȷ������ɴﵽ�ƹ�.
```



- [ ] �����ش�

```
ԭ��:
	�ڷ�����ʵ����ǰ�ȷ��Ͷ���������ݰ�,������ʵ���������ں����Ŀ����ش����ݰ���
	
	����ʹ���checksum�е���,��Ҫ����ȷ��
```



- [x] URG��־λΪ1

```
ԭ��:
	TCPЭ��ͨ������ָ������ƫ�������߷�������ʵ��������ʼλ��,���IDS/IPSû��ʵ�ָù��ܼ��ɲ����ƹ�
	��������,ĿǰUrgent Pointer ֻ������Ϊ1ʱ��Ч
	����������������������һ��ָ��,������˵Ӧ���������С��,����Ҫ������TCP/IP���
```



- [x] ����CheckSum

```
ԭ��:
	��checksum�������,����ʵ������������,����İ��������յ���Ӧ,��IDS����û��ʵ��check���Ĺ��ܵ���������ⲿ��payload,�Ӷ�Ӱ�����
	�������Կ���
```



- [ ] ����

  

��Ч�ƹ�:


- [x] ��������Я������

```
ԭ��:
	����������Я��payload,���ܻ���IDS���ⲿ����������ʵ���ݻ����һ��,���½������
	�Ѳ���,��Ӱ�����
```

- [x] �������к�+FIN/RST

```
ԭ��:
	û��ʵ��״̬���ٵ�IDS/IPS�ڽ�������ʱ,���ܻ�����Ϊ�����Ѿ�����
�Ѳ���,�޷��ƹ�̽��
```

- [x] �������к�

```
ԭ��:
	��������кſ��ܻᵼ��ʵ����״̬���ٵ�IDS/IPS�ڸ��ٹ����н���Ч�����ݰ�����

�Ѳ���,�޷��ƹ�̽��
```





## �о�����



```
https://pkg.go.dev/golang.org/x/net �����Ĺ��ܺ�ǿ��,�������ע
```

```
runtime.GOOS ���ڻ�ȡ����ϵͳ��ʲô
ϵͳ�ײ��һЩԤ��ֵ,�����syscall\types_windows.go��,����socket����漰���Ĺؼ���
```



```


syscall.AF_INET����ʾ������֮�������ͨ��
syscall.AF_UNIX��ʾͬһ̨�����ϵĽ���ͨ��
syscall.AF_INET6��ʾ��IPv6�ķ�ʽ���з�����֮�������ͨ��

syscall.SOCK_RAW����ʾʹ��ԭʼ�׽��֣����Թ���������Э��ͷ��������IP_HDRINCL�Ļ���IP���Э��ͷ��Ҳ���Թ��죬�����������ֵĴ����socket�������socket��
syscall.SOCK_STREAM, ����TCP��socketͨ�ţ�Ӧ�ò�socket��
syscall.SOCK_DGRAM, ����UDP��socketͨ�ţ�Ӧ�ò�socket��

IPPROTO_TCP ����TCPЭ�������
IPPROTO_IP �����κε�IP���ݰ�
IPPROTO_UDP ����UDPЭ�������
IPPROTO_ICMP ����ICMPЭ�������
IPPROTO_RAW ֻ����������IP���ݰ������ܽ������ݡ�

syscall.IPPROTO_RAW == (int)255
```



### TCP CheckSum

����ڳ�����GoдTCP RAW Socket,���Ծ����Լ�ʵ��TCPЭ��ĸ�������

**����net.Dial("ip4:tcp", Dip)**�������ʵ��,����Ҫ�Զ���ipͷ,ֻ��Ҫ�Զ���TCPͷ����

�����˺ܶ�����(���÷�TCP/IP�����),���ڿ���checksum��ʵ�ֻ���

���������,�ⲿ���Ų�����������鷳,һ��checksum���˷���˾�û��Ӧ,��ֱ��������

����ԭ������:

```go
IPv4 SRC + IPv4 DST + IPv4 Protocol(��ӦTCP��Ϊ0x0006) + TCP Segment Length +
TCP Header (checksum�ֶ���Ϊ0) + TCP Options + TCP Payload

����:TCP Segment Length ��ʾTCPͷ���ĳ���+TCP payload�ĳ���

�������ֶ���2bytesΪһ����λ�������,��󳬳�2bytes�Ĵ�С��Χ�����ó����ӵ����ȥ.
����Ϊʲô��2bytes,������Ϊ��TCPЭ��Ķ�����Checksum�ֶεĴ�С�̶�Ϊ2bytes

ʹ��GO����Ĵ��¹�������,�ú����Ǹ�������C����ʵ�ֵ�ԭ���д�õ�

func Checksum(buffer []byte, size uint32) uint16 {

	var checksum uint32
	for i:=0; size > 0; i += 2{
		checksum += uint32(buffer[i]) + uint32(buffer[i+1])<<8
		size -= 2
	}
	checksum = checksum>>16 + (checksum & 0xffff)
	checksum += checksum >> 16
	return (uint16(checksum ^ 0xffff ))
}

ʹ�ú��ֻ�����һЩС����,���Ǽ����������ֵû�к�Go�е�net.Dial���͵Ĵ�С�������,��ȻҲ����˵������Ĳ���.���Ǻ���Ҳ���ø���,�����˸����취����byteλ���е�������.

```

�ο�����:

```
https://stackoverflow.com/questions/66142461/tcp-calculate-checksum#comment127123952_66161909
```





### ϵͳ�Զ�����RST

�����ϻ�˵,�ɹ�����SYN����Ҳ�յ��˷������Ӧ��ACK,���ǻ�û���ü�������һ����ʱ��,ϵͳ���Զ�������˻ظ���һ��RST���������ж���.

�������������,�����������Ļظ�������: RAW socket������������û�о���ϵͳ�ں˵�Э��ջ,����ϵͳ����֪�����Ƿ�����SYN��,����ȴ�ܽ��յ����Է���˵�ACK��,���Ǻ�ϵͳЭ��ջ����Ī������,�͸�����˷�����һ��RST��,�ر�������.

����취:

?	1.�޸�ϵͳ�ں�,(�������ʵ��,���ﲻ��������)

?	2.����ϵͳ������RST��.



��Եڶ����취�Ľ������:

����һ: ͨ��iptables����ϵͳ��RST��

�ŵ�:����

ȱ��:��һlinuxϵͳ��û��iptables��?��Ȼiptables�Ǽ�����ϵͳ�ں����,һ�㶼�а�.

```shell
��ӹ���
sudo iptables -t filter -I OUTPUT -p tcp --dport 80 --tcp-flags RST RST -j DROP

ɾ������
sudo iptables -t filter -D OUTPUT -p tcp --dport 80 --tcp-flags RST RST -j DROP

```

���һ��ϸ��,���������go��:����Ϊʲôд��ô�ϸ�Ĺ���,�����һ��Syn Flood�Ĺ���ԭ��,��Ȼ�����õĻ������Ǳ��ػ���,��Ҫ�����ڷ������ϰ�RST��������,�Ǿ��鷳��.

```
	ruleAdd := fmt.Sprintf("iptables -t filter -I OUTPUT -p tcp -s %s --sport %d -d %s --dport %d  --tcp-flags RST RST -j DROP",sip,sport,dip,dport)
	ruleDel := fmt.Sprintf("iptables -t filter -D OUTPUT -p tcp -s %s --sport %d -d %s --dport %d  --tcp-flags RST RST -j DROP",sip,sport,dip,dport)
	err = exec.Command("/bin/bash","-c",ruleAdd).Run()
	if err != nil {
		log.Fatal(err)
		return
	}
	//TCP������ʱɾ�����iptables�Ĺ���.
	defer func(command *exec.Cmd) {
		err := command.Run()
		if err != nil {

		}
	}(exec.Command("/bin/bash", "-c", ruleDel))
```



������:�Լ�ͨ��IP��ʵ��һ��RST��������.

�ŵ�:ɶʱ�򶼹���

ȱ��:�Լ�����д�鷳!



�ο�����:

https://stackoverflow.com/questions/1188951/in-raw-socket-programming-on-linux-how-can-i-prevent-the-underlying-os-from-res