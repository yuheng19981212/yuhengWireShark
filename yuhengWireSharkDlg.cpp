
// yuhengWireSharkDlg.cpp: 实现文件
//
#include "stdafx.h"
#include <iostream>
#include <winsock2.h>
#include <fstream>
#include <string>

#include "yuhengWireShark.h"
#include "yuhengWireSharkDlg.h"
#include "afxdialogex.h"
#include "header.h"
#include "mstcpip.h"
#pragma comment(lib, "WS2_32")
#define DEF_ICMP_DATA_SIZE  1024
#define MAX_ICMP_PACKET_SIZE 2048

using namespace std;
char packs[100][1600]; //最长1500
int packrows = 0;      //用来记录抓了多少个包

// 用于应用程序“关于”菜单项的 CAboutDlg 对话框

class CAboutDlg : public CDialogEx
{
public:
	CAboutDlg();

// 对话框数据
#ifdef AFX_DESIGN_TIME
	enum { IDD = IDD_ABOUTBOX };
#endif

	protected:
	virtual void DoDataExchange(CDataExchange* pDX);    // DDX/DDV 支持

// 实现
protected:
	DECLARE_MESSAGE_MAP()
};

CAboutDlg::CAboutDlg() : CDialogEx(IDD_ABOUTBOX)
{
}

void CAboutDlg::DoDataExchange(CDataExchange* pDX)
{
	CDialogEx::DoDataExchange(pDX);
}

BEGIN_MESSAGE_MAP(CAboutDlg, CDialogEx)
END_MESSAGE_MAP()


// CyuhengWireSharkDlg 对话框



CyuhengWireSharkDlg::CyuhengWireSharkDlg(CWnd* pParent /*=nullptr*/)
	: CDialogEx(IDD_YUHENGWIRESHARK_DIALOG, pParent)
{
	m_hIcon = AfxGetApp()->LoadIcon(IDR_MAINFRAME);
}

void CyuhengWireSharkDlg::DoDataExchange(CDataExchange* pDX)
{
	CDialogEx::DoDataExchange(pDX);
	DDX_Control(pDX, IDC_LIST1, mainDisplay);
	DDX_Control(pDX, IDC_LIST2, infoDisplay);
	DDX_Control(pDX, IDC_EDIT2, pingAndTraceRoute);
	DDX_Control(pDX, IDC_EDIT3, pingPackNum);
	DDX_Control(pDX, IDC_COMBO1, hostIpSelect);
	DDX_Control(pDX, IDC_COMBO2, packNumSelect);
}

BEGIN_MESSAGE_MAP(CyuhengWireSharkDlg, CDialogEx)
	ON_WM_SYSCOMMAND()
	ON_WM_PAINT()
	ON_WM_QUERYDRAGICON()
	ON_BN_CLICKED(IDC_BUTTON1, &CyuhengWireSharkDlg::OnBnClickedButton1)
	ON_BN_CLICKED(IDC_BUTTON2, &CyuhengWireSharkDlg::OnBnClickedButton2)
	ON_LBN_SELCHANGE(IDC_LIST1, &CyuhengWireSharkDlg::OnLbnSelchangeList1)
	ON_BN_CLICKED(IDC_BUTTON5, &CyuhengWireSharkDlg::OnBnClickedButton5)
	ON_BN_CLICKED(IDC_BUTTON4, &CyuhengWireSharkDlg::OnBnClickedButton4)
	ON_EN_CHANGE(IDC_EDIT3, &CyuhengWireSharkDlg::OnEnChangeEdit3)
	ON_BN_CLICKED(IDC_BUTTON3, &CyuhengWireSharkDlg::OnBnClickedButton3)
END_MESSAGE_MAP()


// CyuhengWireSharkDlg 消息处理程序

BOOL CyuhengWireSharkDlg::OnInitDialog()
{
	CDialogEx::OnInitDialog();

	// 将“关于...”菜单项添加到系统菜单中。


	// IDM_ABOUTBOX 必须在系统命令范围内。
	ASSERT((IDM_ABOUTBOX & 0xFFF0) == IDM_ABOUTBOX);
	ASSERT(IDM_ABOUTBOX < 0xF000);

	CMenu* pSysMenu = GetSystemMenu(FALSE);
	if (pSysMenu != nullptr)
	{
		BOOL bNameValid;
		CString strAboutMenu;
		bNameValid = strAboutMenu.LoadString(IDS_ABOUTBOX);
		ASSERT(bNameValid);
		if (!strAboutMenu.IsEmpty())
		{
			pSysMenu->AppendMenu(MF_SEPARATOR);
			pSysMenu->AppendMenu(MF_STRING, IDM_ABOUTBOX, strAboutMenu);
		}
	}

	// 设置此对话框的图标。  当应用程序主窗口不是对话框时，框架将自动
	//  执行此操作
	SetIcon(m_hIcon, TRUE);			// 设置大图标
	SetIcon(m_hIcon, FALSE);		// 设置小图标

	// TODO: 在此添加额外的初始化代码

	//这里负责初始化本机host地址
	char hostName[200];
	memset(hostName, '\0', sizeof(hostName));
	gethostname(hostName, sizeof(hostName));
	hostent *hptr = gethostbyname(hostName);  //获取用户名
	if (hptr != NULL)
	{
		char **pptr = hptr->h_addr_list;
		while (*pptr != NULL)
		{
			hostIpSelect.AddString(inet_ntoa(*(struct in_addr *)(*pptr)));
			//infoDisplay.AddString(inet_ntoa(*(struct in_addr *)(*pptr)));由消息提示变成下拉框选择，这一行注释掉了吧
			pptr++;
		}
	}
	else
	{
		char err[20];
		itoa(WSAGetLastError(), err, 20);
		CString info(err);
		infoDisplay.AddString("未能获取到本机地址，错误码:" + info);
	}
	hostIpSelect.SetCurSel(0);
	//初始化本机host结束

	packNumSelect.AddString("1");
	packNumSelect.AddString("2");
	packNumSelect.AddString("3");
	packNumSelect.AddString("4");
	packNumSelect.AddString("5");
	packNumSelect.AddString("6");
	packNumSelect.AddString("7");
	packNumSelect.AddString("8");
	packNumSelect.AddString("9");
	packNumSelect.AddString("10");
	packNumSelect.AddString("20");
	packNumSelect.AddString("30");
	packNumSelect.AddString("40");
	packNumSelect.AddString("50");

	return TRUE;  // 除非将焦点设置到控件，否则返回 TRUE
}

void CyuhengWireSharkDlg::OnSysCommand(UINT nID, LPARAM lParam)
{
	if ((nID & 0xFFF0) == IDM_ABOUTBOX)
	{
		CAboutDlg dlgAbout;
		dlgAbout.DoModal();
	}
	else
	{
		CDialogEx::OnSysCommand(nID, lParam);
	}
}

// 如果向对话框添加最小化按钮，则需要下面的代码
//  来绘制该图标。  对于使用文档/视图模型的 MFC 应用程序，
//  这将由框架自动完成。

void CyuhengWireSharkDlg::OnPaint()
{
	if (IsIconic())
	{
		CPaintDC dc(this); // 用于绘制的设备上下文

		SendMessage(WM_ICONERASEBKGND, reinterpret_cast<WPARAM>(dc.GetSafeHdc()), 0);

		// 使图标在工作区矩形中居中
		int cxIcon = GetSystemMetrics(SM_CXICON);
		int cyIcon = GetSystemMetrics(SM_CYICON);
		CRect rect;
		GetClientRect(&rect);
		int x = (rect.Width() - cxIcon + 1) / 2;
		int y = (rect.Height() - cyIcon + 1) / 2;

		// 绘制图标
		dc.DrawIcon(x, y, m_hIcon);
	}
	else
	{
		CDialogEx::OnPaint();
	}
}

//当用户拖动最小化窗口时系统调用此函数取得光标
//显示。
HCURSOR CyuhengWireSharkDlg::OnQueryDragIcon()
{
	return static_cast<HCURSOR>(m_hIcon);
}

void CyuhengWireSharkDlg::OnBnClickedButton1()
{
	packrows = 0;//归位
	memset(packs, 0, sizeof(packs));
	//创建原始套接字
	SOCKET yuhengSock = socket(AF_INET, SOCK_RAW, IPPROTO_IP);
	if (yuhengSock == INVALID_SOCKET)
	{
		char err[20];
		itoa(WSAGetLastError(), err, 20);
		CString info(err);
		infoDisplay.AddString("原始套接字加载失败，错误码:" + info);
	}else infoDisplay.AddString("原始套接字加载成功");

	
	//从框框里获取本地地址信息
	CString bindAddr;
	//bindingIP.GetWindowTextA(bindAddr);这一行是从输入框中获取信息

	int ipSelect = hostIpSelect.GetCurSel();
	hostIpSelect.GetLBText(ipSelect, bindAddr); //从下拉框中获取信息

	SOCKADDR_IN addr_in;
	addr_in.sin_family = AF_INET;
	addr_in.sin_port = htons(0);
	addr_in.sin_addr.S_un.S_addr = inet_addr(bindAddr);

	if (bind(yuhengSock, (SOCKADDR*)&addr_in, sizeof(SOCKADDR)) == SOCKET_ERROR)
	{
		char err[20];
		itoa(WSAGetLastError(), err, 20);
		CString info(err);
		infoDisplay.AddString("绑定失败，错误码:" + info);
	}

	//设置混杂模式
	DWORD dwValue = 1;
	if (ioctlsocket(yuhengSock, SIO_RCVALL, &dwValue) != 0)
	{
		char err[20];
		itoa(WSAGetLastError(), err, 20);
		CString info(err);
		infoDisplay.AddString("设置混杂模式失败，错误码:" + info);
	}
	else infoDisplay.AddString("网卡已经设置为在混杂模式下工作");

	//从这里开始抓取IP分组 分组以全局变量进行存储，便于导出
	//定义的是[100][1600]的数组
	CString numStr;
	CString ipInput;
	packNumSelect.GetWindowText(ipInput);
	if (ipInput.IsEmpty())                 //下拉框也是可以输入的
	{
		int numSelect = packNumSelect.GetCurSel();
		packNumSelect.GetLBText(numSelect, numStr);
	}
	else {
		numStr = ipInput;
	}
	int packNum = atoi(numStr);
	packrows = packNum;  //存一下实际使用的行数
	//开始抓包
	infoDisplay.AddString("正在抓包,一共" + numStr + "个");
	for (int i = 0; i < packNum; i++)
	{
		if (i >= 100) break;
		int recLength = recv(yuhengSock, packs[i], 1600, 0);
		if (recLength<=0)
		{
			char err[20];
			itoa(WSAGetLastError(), err, 20);
			CString info(err);
			infoDisplay.AddString("抓包失败，错误码:" + info);
			return;
		}
	}
	infoDisplay.AddString("抓取完毕");
	for (int j=0;j<packNum;j++)
	{
		CString num;
		num.Format("第%d个IP数据包", j + 1);
		mainDisplay.AddString(num);
		DecodeIPpacket(packs[j]);
	}	
}
void CyuhengWireSharkDlg::DecodeIPpacket(char *pData)
{
	ipHeader *pIPHdr = (ipHeader*) pData;
	in_addr source, dest;
	char SourceIp[32], DestIp[32];
	//取出源IP地址和目的IP地址
	source.S_un.S_addr = pIPHdr->nSourIP;
	dest.S_un.S_addr = pIPHdr->nDestIp;
	strcpy(SourceIp, inet_ntoa(source));
	strcpy(DestIp, inet_ntoa(dest));
	mainDisplay.AddString(CString("源地址:")+SourceIp+CString("    ===发往==>>   ")+ CString("目的地址:")+DestIp);//地址
	
	int HeaderLength = (pIPHdr->bVerAndHLen & 0xf0) * sizeof(unsigned int);//头部长度
	switch (pIPHdr->bProtocol)
	{
	case IPPROTO_TCP:
		mainDisplay.AddString("这是一个TCP报文");
		DecodeTcpPacket(pData+ HeaderLength);
		break;
	case IPPROTO_UDP:
		mainDisplay.AddString("这是一个UDP报文");
		DecodeUdpPacket(pData + HeaderLength);
		break;
	case IPPROTO_ICMP:
		mainDisplay.AddString("这是一个ICMP报文");
		DecodeIcmpPacket(pData + HeaderLength);
		break;
	default:
		CString out;
		out.Format("其它报文：协议号%d", pIPHdr->bProtocol);
		mainDisplay.AddString(out);
	}
	mainDisplay.AddString("*****************************************************************************");

}

void CyuhengWireSharkDlg::DecodeTcpPacket(char * pData)
{
	tcpHeader *pTcpHdr = (tcpHeader*)pData;
	CString out;
	out.Format("TCP源端口:%d  ==>>  目的端口:%d", ntohs(pTcpHdr->nSourPort), ntohs(pTcpHdr->nDestPort));
	mainDisplay.AddString(out);
}

void CyuhengWireSharkDlg::DecodeUdpPacket(char *pData)
{
	udpHeader *pUdpHdr = (udpHeader*)pData;
	CString out;
	out.Format("UDP源端口:%d  ==>>  目的端口:%d", ntohs(pUdpHdr->nSourPort), ntohs(pUdpHdr->nDestPort));
	mainDisplay.AddString(out);

}
void CyuhengWireSharkDlg::DecodeIcmpPacket(char *pData)
{
	IcmpHeader *pICMPHdr = (IcmpHeader*)pData;
	if (pICMPHdr->icmp_type == 3)
	{
		switch (pICMPHdr->icmp_code)
		{
		case 0:
			mainDisplay.AddString("内容:目的网络不可达!"); break;
		case 1:
			mainDisplay.AddString("内容:目的主机不可达!"); break;
		case 6:
			mainDisplay.AddString("内容:不知道的目的网络!"); break;
		case 7:
			mainDisplay.AddString("内容:不知道的目的主机!"); break;
		default:
			infoDisplay.AddString("内容:探测时出现未知错误!"); break;
		}
	}

}

void CyuhengWireSharkDlg::OnBnClickedButton2()
{
	// TODO: 在此添加控件通知处理程序代码
}


void CyuhengWireSharkDlg::OnLbnSelchangeList1()
{
	// TODO: 在此添加控件通知处理程序代码
}



//路由追踪
unsigned short Checksum(unsigned short* pBuf, int iSize) //icmp校验和计算函数
{
	unsigned long cksum = 0;
	while (iSize > 1)
	{
		cksum += *pBuf++;
		iSize -= sizeof(unsigned short);
	}
	if (iSize)
		cksum += *(char*)pBuf;
	cksum = (cksum >> 16) + (cksum & 0xffff);
	cksum += (cksum >> 16);
	return (unsigned short)(~cksum);
}
void CyuhengWireSharkDlg::OnBnClickedButton5()//路由追踪
{

	infoDisplay.AddString("请输入目的IP地址或者IP");
	infoDisplay.AddString("正在对最多三十个跃点进行追踪,请耐心等待");
	CString szDestIp;
	pingAndTraceRoute.GetWindowTextA(szDestIp);
	unsigned long ulDestIP = inet_addr(szDestIp);
	if (ulDestIP == INADDR_NONE)
	{
		//转换不成功时按域名解析 
		hostent* pHostent = gethostbyname(szDestIp);
		if (pHostent != NULL)
			ulDestIP = (*(in_addr*)pHostent->h_addr).s_addr;
		else //解析主机名失败 
		{
			infoDisplay.AddString("不能解析域名\n");
			return;
		}
	}
	mainDisplay.AddString(CString("路由跟踪:")+ szDestIp+ "("+ inet_ntoa(*(in_addr*)(&ulDestIP))+ ")");
	//创建原始套节字，绑定到本地端口
	SOCKET rawSocket = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);
	sockaddr_in in; 
	in.sin_family = AF_INET;
	in.sin_port = 0;
	in.sin_addr.S_un.S_addr = INADDR_ANY;
	if (bind(rawSocket, (sockaddr*)&in, sizeof(in)) == SOCKET_ERROR)
	{
		infoDisplay.AddString("地址绑定失败\n");
		return ;
	}
	int nTime = 10 * 1000;
	setsockopt(rawSocket, SOL_SOCKET, SO_RCVTIMEO, (char*)&nTime, sizeof(nTime));
	//构造ICMP包
	char IcmpSendBuf[sizeof(IcmpHeader) + DEF_ICMP_DATA_SIZE];
	char IcmpRecvBuf[MAX_ICMP_PACKET_SIZE];//接收缓存
	memset(IcmpSendBuf, 0, sizeof(IcmpSendBuf));
	memset(IcmpRecvBuf, 0, sizeof(IcmpRecvBuf));
	//填充包 
	IcmpHeader* pIcmpHeader = (IcmpHeader*)IcmpSendBuf;
	pIcmpHeader->icmp_type = 8;
	pIcmpHeader->icmp_id = 0;
	pIcmpHeader->icmp_id = (unsigned short)GetCurrentProcessId();
	memset(IcmpSendBuf + sizeof(IcmpHeader), '\0', DEF_ICMP_DATA_SIZE);  //填充
	//填充目的地址
	sockaddr_in destAddr;
	destAddr.sin_family = AF_INET;
	destAddr.sin_port = htons(22);
	destAddr.sin_addr.S_un.S_addr = ulDestIP;
	int nRet, nTick, nTTL = 1, iSeqNo = 0;
	//发送报文并接收路由器的差错报告报文
	IcmpHeader *pICMPHdr;  //指向ICMP报文首部的指针
	char *szIP;
	SOCKADDR_IN recvAddr;
	int n;
	mainDisplay.AddString("下面是路由追踪程序返回的结果");
	do
	{
		/***设置TTL值***/
		setsockopt(rawSocket, IPPROTO_IP, IP_TTL, (char*)&nTTL, sizeof(nTTL));
		nTick = GetTickCount();
		bool timeout = false;
		/*** 填写ICMP报文的序列号并计算校验和***/
		((IcmpHeader*)IcmpSendBuf)->icmp_checksum = 0;
		((IcmpHeader*)IcmpSendBuf)->icmp_sequence = htons(iSeqNo++);
		((IcmpHeader*)IcmpSendBuf)->icmp_checksum = Checksum((unsigned short*)IcmpSendBuf, sizeof(IcmpHeader) + DEF_ICMP_DATA_SIZE);
		nRet = sendto(rawSocket, IcmpSendBuf, sizeof(IcmpSendBuf), 0,(sockaddr*)&destAddr, sizeof(destAddr));
		if (nRet == SOCKET_ERROR)
		{
			infoDisplay.AddString("发送数据出错!");
			return;
		}
		//接收ICMP
		int nLen = sizeof(recvAddr);
		n = 0;
		do {
			n++;
			nRet = recvfrom(rawSocket, IcmpRecvBuf, sizeof(IcmpRecvBuf), 0, (sockaddr*)&recvAddr, &nLen);
			if (nRet == SOCKET_ERROR)    //这里我改了书上的写法，超时的时候应该继续探测，书上写的不太科学，遇到第一个超时就会终止
			{
				  if (WSAGetLastError()==WSAETIMEDOUT)
				  {
					  timeout = true;
					  break;
				  }
				  else {
					  infoDisplay.AddString("接收数据错误");
					  closesocket(rawSocket);
					  WSACleanup();
				  }
			}
			pICMPHdr = (IcmpHeader*)&IcmpRecvBuf[20];
			szIP = inet_ntoa(recvAddr.sin_addr);
			if (pICMPHdr->icmp_type == 11 || pICMPHdr->icmp_type == 0 || pICMPHdr->icmp_type == 3) break;
		} while (n < 10);                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                 
		if (n > 10)continue;
		CString info;
		if (timeout)
		{
			CString info;
			info.Format("在第%d个路由器超时!可能是遇到了防火墙", nTTL);
			timeout = true;
			mainDisplay.AddString(info);
		} 
		else
		{
			info.Format("第%d个路由器，IP地址：%s 用时%d毫秒\n", nTTL, szIP, GetTickCount() - nTick);
			mainDisplay.AddString(info);
		}
		
		if (pICMPHdr->icmp_type == 3)
		{
			switch (pICMPHdr->icmp_code)
			{
			case 0: 
				mainDisplay.AddString("目的网络不可达!");break;
			case 1:
				mainDisplay.AddString("目的主机不可达!"); break;
			case 6: 
				mainDisplay.AddString("不知道的目的网络!"); break;
			case 7: 
				mainDisplay.AddString("不知道的目的主机!"); break;
			default:
				infoDisplay.AddString("探测时出现未知错误!"); break;
			}
		}
		if (destAddr.sin_addr.S_un.S_addr == recvAddr.sin_addr.S_un.S_addr)
		{
			mainDisplay.AddString("目标可达,追踪成功"); break;
		}
	} while (nTTL++ < 30);
	closesocket(rawSocket);
}

void CyuhengWireSharkDlg::OnBnClickedButton4()//ping
{
	const int DATALEN = 32; //包大小,32+32 首部+_填充
	int pingNum = 8;        //包数量,默认值8
	CString temp;
	pingPackNum.GetWindowTextA(temp);
	if (temp!="")
		pingNum = atoi(temp);
	mainDisplay.AddString("**************************ping开始**************************");
	infoDisplay.AddString("ping开始");
	CString szDestIp;
	pingAndTraceRoute.GetWindowTextA(szDestIp);
	/***将点分十进制IP地址转换为32位二进制表示的IP地址***/
	unsigned long ulDestIP = inet_addr(szDestIp);
	/****转换不成功时按域名解析****/
	if (ulDestIP == INADDR_NONE)
	{
		hostent* pHostent = gethostbyname(szDestIp);
		if (pHostent != NULL)
			ulDestIP = (*(in_addr*)pHostent->h_addr).s_addr;
		else //解析主机名失败
		{
			char err[20];
			itoa(WSAGetLastError(), err, 20);
			CString info(err);
			infoDisplay.AddString("域名解析失败，错误码:" + info);
		}
	}
	/**** 创建收发ICMP包的原始套接字***/
	SOCKET pingSocket = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);
	/***设置接收超时时间***/
	int nTime = 1000;
	setsockopt(pingSocket, SOL_SOCKET, SO_RCVTIMEO, (char*)&nTime, sizeof(nTime));
	/***设置ICMP包发送的目的地址***/
	SOCKADDR_IN dest;
	dest.sin_family = AF_INET;
	dest.sin_port = htons(0);
	dest.sin_addr.S_un.S_addr = ulDestIP;
	/***创建ICMP包***/
	char buff[sizeof(IcmpHeader) + DATALEN];
	IcmpHeader* pIcmp = (IcmpHeader*)buff;
	/***填写ICMP包数据***/
	pIcmp->icmp_type = 8;	// ICMP回送请求
	pIcmp->icmp_code = 0;
	pIcmp->icmp_id = (unsigned short)GetCurrentProcessId();//获取进程号作为ID 
	pIcmp->icmp_timestamp = 0; //时间戳暂设置为0，具体值发送时再填
	pIcmp->icmp_checksum = 0;  //校验和在计算前应先设置为0
	pIcmp->icmp_sequence = 0;  //初始序列号
	/***填充数据部分，可以为任意***/
	memset(&buff[sizeof(IcmpHeader)], '\0', DATALEN);
	/***调用connect()函数为原始套接字指定通信对端地址***/
	connect(pingSocket, (SOCKADDR *)&dest, sizeof(dest));
	/***收发ICMP报文***/
	int n = 0;
	bool timeOut;
	unsigned short	nSeq = 0;//发送的ICMP报文的序号
	char recvBuf[32 + DATALEN];//定义接收缓冲区
	SOCKADDR_IN from;  //保存收到的数据的源地址
	int nLen = sizeof(from);  //地址长度
	IcmpHeader* pingReceive;  //指向ICMP报文首部的指针
	while (TRUE)
	{
		static int nCount = 0;
		int nRet;
		if (nCount++ == pingNum)
			break;
		/***填写发送前才能填写的一些字段并发送ICMP包***/
		pIcmp->icmp_checksum = 0;
		pIcmp->icmp_timestamp = GetTickCount();//时间戳
		pIcmp->icmp_sequence = nSeq++;  //包序号
		pIcmp->icmp_checksum = Checksum((unsigned short*)buff, sizeof(IcmpHeader) + DATALEN);
		nRet = send(pingSocket, buff, sizeof(IcmpHeader) + DATALEN, 0);
		if (nRet == SOCKET_ERROR)
		{
			char err[20];
			itoa(WSAGetLastError(), err, 20);
			CString info(err);
			infoDisplay.AddString("发送失败，错误码:" + info);
			closesocket(pingSocket);
			return;
		}
		//接收对方返回的ICMP应答
		timeOut = FALSE;
		n = 0;
		do {
			n++;//接收预期ICMP应答报文的尝试次数加1
			memset((void *)recvBuf, 0, sizeof(recvBuf));
			nRet = recvfrom(pingSocket, recvBuf, sizeof(recvBuf), 0, (sockaddr*)&from, &nLen);
			if (nRet == SOCKET_ERROR)
			{

				if (WSAGetLastError() == WSAETIMEDOUT)
				{
					timeOut = true;
					break;
				}
				else {
					infoDisplay.AddString("接收数据错误");
					closesocket(pingSocket);
					WSACleanup();
				}
			}
			pingReceive = (IcmpHeader*)(recvBuf + 20);
			//收到的数据包含20个字节的IP首部，加20才是ICMP首部位置 
			if (pingReceive->icmp_id != GetCurrentProcessId())
				//收到报文是否为本程序发送的请求报文的应答报文
			{
				//不是则重新接收	
				infoDisplay.AddString("收到一个非预期的ICMP报文，忽略！\n");
			}
			else  //是则退出循环
				break;
		} while (n < 10);//重新接收次数不超过10则继续重试
		if (n > 10)// 收到太多非预期的ICMP报文则退出
		{
			infoDisplay.AddString("对方机器向本机发送了太多的ICMP报文");
			closesocket(pingSocket);
			WSACleanup();
		}
		if (timeOut)continue;  //接收超时则发送下一个ICPM报文
		/****解析接收到的ICMP包****/
		int nTick = GetTickCount();
		if (nRet < 20 + sizeof(IcmpHeader))  //收到的报文长度不足则不予解析
		{
			infoDisplay.AddString("报文长度太短，丢弃！\n");
			continue;
		}
		else
		{
			//解析收到报文
			CString message;
			message.Format("IMCP包序号:%d  大小:%d  来自:%s  响应时间:%d(ms)",(pingReceive->icmp_sequence)+1,nRet,inet_ntoa(from.sin_addr),nTick-pingReceive->icmp_timestamp);
			mainDisplay.AddString(message);
			Sleep(1000);  //延时1秒再发送下一个数据包
		}
	}
	infoDisplay.AddString("ping结束");
	mainDisplay.AddString("**************************ping结束**************************");
}


void CyuhengWireSharkDlg::OnEnChangeEdit3()
{
}


void CyuhengWireSharkDlg::OnBnClickedButton3()//这个函数用于保存抓包的数组
{
	
	fstream file;
	file.open("c:/test/1.txt");
	for (int i=0;i<packrows;i++)
	{
		string fileContent(packs[i]);
		file << fileContent;
	}
}
