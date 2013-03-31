// ProcProtectMFCDlg.cpp : 实现文件
//

#include "stdafx.h"
#include "ProcProtectMFC.h"
#include "ProcProtectMFCDlg.h"
#include <winioctl.h>
#include "..\ProcProtect\IOCTL.h"

#define SymLinkName "\\\\.\\ProcProtect"
#define ExeName "notepad.exe"
HANDLE hDevice = NULL;

#ifdef _DEBUG
#define new DEBUG_NEW
#endif


// 用于应用程序“关于”菜单项的 CAboutDlg 对话框

class CAboutDlg : public CDialog
{
public:
	CAboutDlg();

// 对话框数据
	enum { IDD = IDD_ABOUTBOX };

	protected:
	virtual void DoDataExchange(CDataExchange* pDX);    // DDX/DDV 支持

// 实现
protected:
	DECLARE_MESSAGE_MAP()
};

CAboutDlg::CAboutDlg() : CDialog(CAboutDlg::IDD)
{
}

void CAboutDlg::DoDataExchange(CDataExchange* pDX)
{
	CDialog::DoDataExchange(pDX);
}

BEGIN_MESSAGE_MAP(CAboutDlg, CDialog)
END_MESSAGE_MAP()


// CProcProtectMFCDlg 对话框




CProcProtectMFCDlg::CProcProtectMFCDlg(CWnd* pParent /*=NULL*/)
	: CDialog(CProcProtectMFCDlg::IDD, pParent)
{
	m_hIcon = AfxGetApp()->LoadIcon(IDR_MAINFRAME);
}

void CProcProtectMFCDlg::DoDataExchange(CDataExchange* pDX)
{
	CDialog::DoDataExchange(pDX);
}

BEGIN_MESSAGE_MAP(CProcProtectMFCDlg, CDialog)
	ON_WM_SYSCOMMAND()
	ON_WM_PAINT()
	ON_WM_QUERYDRAGICON()
	//}}AFX_MSG_MAP
	ON_BN_CLICKED(IDC_InstallHook, &CProcProtectMFCDlg::OnBnClickedInstallhook)
	ON_BN_CLICKED(IDC_Start, &CProcProtectMFCDlg::OnBnClickedStart)
	ON_BN_CLICKED(IDC_UnInstallHook, &CProcProtectMFCDlg::OnBnClickedUninstallhook)
	ON_BN_CLICKED(IDC_SaveExeInfo, &CProcProtectMFCDlg::OnBnClickedSaveexeinfo)
END_MESSAGE_MAP()


// CProcProtectMFCDlg 消息处理程序

BOOL CProcProtectMFCDlg::OnInitDialog()
{
	CDialog::OnInitDialog();

	// 将“关于...”菜单项添加到系统菜单中。

	// IDM_ABOUTBOX 必须在系统命令范围内。
	ASSERT((IDM_ABOUTBOX & 0xFFF0) == IDM_ABOUTBOX);
	ASSERT(IDM_ABOUTBOX < 0xF000);

	CMenu* pSysMenu = GetSystemMenu(FALSE);
	if (pSysMenu != NULL)
	{
		CString strAboutMenu;
		strAboutMenu.LoadString(IDS_ABOUTBOX);
		if (!strAboutMenu.IsEmpty())
		{
			pSysMenu->AppendMenu(MF_SEPARATOR);
			pSysMenu->AppendMenu(MF_STRING, IDM_ABOUTBOX, strAboutMenu);
		}
	}

	// 设置此对话框的图标。当应用程序主窗口不是对话框时，框架将自动
	//  执行此操作
	SetIcon(m_hIcon, TRUE);			// 设置大图标
	SetIcon(m_hIcon, FALSE);		// 设置小图标

	// TODO: 在此添加额外的初始化代码
	// 这里调用驱动
	hDevice = CreateFile(SymLinkName,
		GENERIC_READ | GENERIC_WRITE,
		0,
		NULL,
		OPEN_EXISTING,
		FILE_ATTRIBUTE_NORMAL,
		NULL );

	if (hDevice == INVALID_HANDLE_VALUE)
	{
		MessageBox("CreateFile Failed!");
		return FALSE;
	}

	return TRUE;  // 除非将焦点设置到控件，否则返回 TRUE
}

void CProcProtectMFCDlg::OnSysCommand(UINT nID, LPARAM lParam)
{
	if ((nID & 0xFFF0) == IDM_ABOUTBOX)
	{
		CAboutDlg dlgAbout;
		dlgAbout.DoModal();
	}
	else
	{
		CDialog::OnSysCommand(nID, lParam);
	}
}

// 如果向对话框添加最小化按钮，则需要下面的代码
//  来绘制该图标。对于使用文档/视图模型的 MFC 应用程序，
//  这将由框架自动完成。

void CProcProtectMFCDlg::OnPaint()
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
		CDialog::OnPaint();
	}
}

//当用户拖动最小化窗口时系统调用此函数取得光标
//显示。
HCURSOR CProcProtectMFCDlg::OnQueryDragIcon()
{
	return static_cast<HCURSOR>(m_hIcon);
}


void CProcProtectMFCDlg::OnBnClickedInstallhook()
{
	// TODO: 在此添加控件通知处理程序代码
	BOOL bRet;
	DWORD dwOutput;
	bRet = DeviceIoControl(hDevice, IOCTL_Install_SSDTHook,
		NULL,0,
		NULL, 0,
		&dwOutput, NULL);
	if (bRet == FALSE)
	{
		MessageBox("IOCTL_Install_SSDTHook Failed");
		return;
	}
/*
	int iPID = GetCurrentProcessId();
	bRet = DeviceIoControl(hDevice, IOCTL_AddPortectProc,
		&iPID,sizeof(iPID),
		NULL, 0,
		&dwOutput, NULL);
	if (bRet == FALSE)
	{
		MessageBox("IOCTL_AddPortectProc Failed");
		return;
	}
*/
}

void CProcProtectMFCDlg::OnBnClickedStart()
{
	// TODO: 在此添加控件通知处理程序代码
	/*
	// 启动notepad
	STARTUPINFO si; //一些必备参数设置
	memset(&si, 0, sizeof(STARTUPINFO));
	si.cb = sizeof(STARTUPINFO);
	si.dwFlags = STARTF_USESHOWWINDOW;
	si.wShowWindow = SW_SHOW;
	PROCESS_INFORMATION pi; //必备参数设置结束
	BOOL bRet = CreateProcess(NULL,ExeName,NULL,NULL,FALSE,0,NULL,NULL,&si,&pi);
	*/
	
	BOOL bRet;
	DWORD dwOutput;
	int iPID = 2100;
	bRet = DeviceIoControl(hDevice, IOCTL_AddPortectProc,
		&iPID,sizeof(iPID),
		NULL, 0,
		&dwOutput, NULL);
	if (bRet == FALSE)
	{
		MessageBox("IOCTL_AddPortectProc Failed");
		return;
	}
}

void CProcProtectMFCDlg::OnBnClickedUninstallhook()
{
	// TODO: 在此添加控件通知处理程序代码
	DWORD dwOutput;
	BOOL bRet = DeviceIoControl(hDevice, IOCTL_UnInstall_SSDTHook,
		NULL, 0, 
		NULL, 0,
		&dwOutput, NULL);
	if (bRet == FALSE)
	{
		MessageBox("IOCTL_UnInstall_SSDTHook Failed");
		return;
	}
}


void CProcProtectMFCDlg::OnBnClickedSaveexeinfo()
{
	// TODO: 在此添加控件通知处理程序代码
	DWORD dwOutput;
	WCHAR wcExe[0x200];
//	wcscpy(wcExe,L"C:\\windows\\notepad.exe");
//	wcscpy(wcExe,L"C:\\Program Files\\Microsoft Visual Studio 9.0\\Common7\\IDE\\devenv.exe");
	wcscpy(wcExe,L"c:\\windows\\system32\\GDI32.DLL");
	
	BOOL bRet = DeviceIoControl(hDevice, IOCTL_SetSafeExe,
		wcExe, 0x200, 
		NULL, 0,
		&dwOutput, NULL);
	if (bRet == FALSE)
	{
		MessageBox("IOCTL_UnInstall_SSDTHook Failed");
		return;
	}
}
