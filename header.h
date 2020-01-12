#include "stdafx.h"

//IP��ͷ
typedef struct
{
	unsigned char bVerAndHLen;                    //�汾��Ϣ��ǰ4λ����ͷ���ȣ���4λ��
	unsigned char bTypeOfService;                 //��������
	unsigned short nIpLength;                     //���ݰ�����
	unsigned short nID;							  //���ݰ���ʶ
	unsigned short nReserved;                     //�����ֶ�
	unsigned char bTTL;                           //����ʱ��
	unsigned char bProtocol;                      //Э������
	unsigned short nCheckSum;                     //У���
	unsigned int nSourIP;						  //ԴIP
	unsigned int nDestIp;                         //Ŀ��IP
}ipHeader,*ptr_ipHeader;

//TCP��ͷ
typedef struct
{
	unsigned short nSourPort;                     //Դ�˿ں�
	unsigned short nDestPort;					  //Ŀ�Ķ˿ں�
	unsigned int nSeqNum;						  //���к�
	unsigned int nAcknowledgeNum;				  //ȷ�Ϻ�
	unsigned char bDataOfSet;					  //��4λ��������ƫ��
	unsigned char bflags;					      //��6λ����URG,ACK,PSH,RST,SYN,FIN
	unsigned short nWindowSize;					  //���ڴ�С
	unsigned short nCheckSum;					  //У���
	unsigned short nrgentPointer;			      //��������ƫ����
}tcpHeader,*ptr_tcpHeader;

//UDP��ͷ
typedef struct
{
	unsigned short nSourPort;				 	  //Դ�˿ں�
	unsigned short nDestPort;				 	  //Ŀ�Ķ˿ں�
	unsigned short nLength;						  //���ݰ�����
	unsigned short nCheckSum;					  //У���
}udpHeader, *ptr_udpHeader;

//ICMP��ͷ
typedef struct
{
	unsigned char   bIcmpType;			   		 // ��Ϣ����
	unsigned char   bIcmpCode;					 // ����
	unsigned short  nIcmpChecksum;	             // У���
	unsigned short  nIcmpId;		             // ����Ωһ��ʶ�������ID�ţ�ͨ������Ϊ����ID
	unsigned short  nIcmpSequence;	             // ���к�
	unsigned long   nIcmpTime;              // ʱ���
} IcmpHeader;

//����Ϣͷ
typedef struct
{	
	unsigned short nLength;						  //���ݰ�����
	unsigned short nProtocol;				      //Э������
	unsigned int nSourIp;						  //ԴIP
	unsigned int nDestIp;						  //Ŀ��IP
	unsigned short nSourPort;				      //Դ�˿�
	unsigned short nDestPort;				      //Ŀ�Ķ˿�
}packInfo,*ptr_packInfo;