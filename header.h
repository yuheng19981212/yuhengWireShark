#include "stdafx.h"

//IP报头
typedef struct
{
	unsigned char bVerAndHLen;                    //版本信息（前4位）和头长度（后4位）
	unsigned char bTypeOfService;                 //服务类型
	unsigned short nIpLength;                     //数据包长度
	unsigned short nID;							  //数据包标识
	unsigned short nReserved;                     //保留字段
	unsigned char bTTL;                           //生成时间
	unsigned char bProtocol;                      //协议类型
	unsigned short nCheckSum;                     //校验和
	unsigned int nSourIP;						  //源IP
	unsigned int nDestIp;                         //目的IP
}ipHeader,*ptr_ipHeader;

//TCP报头
typedef struct
{
	unsigned short nSourPort;                     //源端口号
	unsigned short nDestPort;					  //目的端口号
	unsigned int nSeqNum;						  //序列号
	unsigned int nAcknowledgeNum;				  //确认号
	unsigned char bDataOfSet;					  //高4位代表数据偏移
	unsigned char bflags;					      //低6位代表URG,ACK,PSH,RST,SYNhe,FIN
	unsigned short nWindowSize;					  //窗口大小
	unsigned short nCheckSum;					  //校验和
	unsigned short nrgentPointer;			      //紧急数据偏移量
}tcpHeader,*ptr_tcpHeader;

typedef struct
{
	unsigned short nSourPort;				 	  //源端口号
	unsigned short nDestPort;				 	  //目的端口号
	unsigned short nLength;						  //数据包长度
	unsigned short nCheckSum;					  //校验和
}udpHeader, *ptr_udpHeader;

typedef struct
{
	unsigned char   icmp_type;		// 消息类型
	unsigned char   icmp_code;		// 代码
	unsigned short  icmp_checksum;	// 校验和
	unsigned short  icmp_id;		// 用来惟一标识此请求的ID号，通常设置为进程ID
	unsigned short  icmp_sequence;	// 序列号
	unsigned long   icmp_timestamp; // 时间戳
} IcmpHeader;

typedef struct
{	
	unsigned short nLength;						  //数据包长度
	unsigned short nProtocol;				      //协议类型
	unsigned int nSourIp;						  //源IP
	unsigned int nDestIp;						  //目的IP
	unsigned short nSourPort;				      //源端口
	unsigned short nDestPort;				      //目的端口
}packInfo,*ptr_packInfo;