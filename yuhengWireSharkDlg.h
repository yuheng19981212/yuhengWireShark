
// yuhengWireSharkDlg.h: 头文件
//

#pragma once


// CyuhengWireSharkDlg 对话框
class CyuhengWireSharkDlg : public CDialogEx
{
// 构造
public:
	CyuhengWireSharkDlg(CWnd* pParent = nullptr);	// 标准构造函数

// 对话框数据
#ifdef AFX_DESIGN_TIME
	enum { IDD = IDD_YUHENGWIRESHARK_DIALOG };
#endif

	protected:
	virtual void DoDataExchange(CDataExchange* pDX);	// DDX/DDV 支持


// 实现
protected:
	HICON m_hIcon;

	// 生成的消息映射函数
	virtual BOOL OnInitDialog();
	afx_msg void OnSysCommand(UINT nID, LPARAM lParam);
	afx_msg void OnPaint();
	afx_msg HCURSOR OnQueryDragIcon();
	DECLARE_MESSAGE_MAP()
public:
	// 用来展示抓包的数据
	afx_msg void OnBnClickedButton1();
	afx_msg void OnBnClickedButton2();
	afx_msg void OnLbnSelchangeList1();
	// 包信息
	CListBox mainDisplay;
	// 展示运行信息
	CListBox infoDisplay;
	//抓包主入口
	afx_msg void OnBnClickedButton5();
	void DecodeIPpacket(char *pData);
	void DecodeTcpPacket(char *pData);
	void DecodeUdpPacket(char *pData);
	void DecodeIcmpPacket(char *pData);
	afx_msg void OnBnClickedButton4();
	CEdit pingAndTraceRoute;
	// 发送的ping包数量
	CEdit pingPackNum;
	CComboBox hostIpSelect;
	CComboBox packNumSelect;
	afx_msg void OnBnClickedButton6();
	afx_msg void OnBnClickedButton3();
	afx_msg void OnLbnSelchangeList2();
};
