from tkinter import *
from tkinter import ttk
from portScanner import multi_process_tcp_scan
from nmapScanner import nmap_os_scan, nmap_ping_scan
import ms17_010_checker


def treeViewFree(table):
    x = table.get_children()
    for item in x:
        table.delete(item)


def pingScan():
    yieldStatusLabel.configure(text='•Scanning', fg='red')
    yieldStatusLabel.update()
    ipAddr = yieldInputAddr.get()
    index = 0
    treeViewFree(yieldResult)
    for hosts in nmap_ping_scan(ipAddr):
        yieldResult.insert('', index, values=(hosts, "UP"))
        index = index + 1
    yieldStatusLabel.configure(text='•IDLE', fg='green')
    yieldStatusLabel.update()


def portScan():
    portStatusLabel.configure(text='•Scanning', fg='red')
    portStatusLabel.update()
    ipAddr = portInputAddr.get()
    index = 0
    treeViewFree(portResult)
    scanResult = multi_process_tcp_scan(ipAddr, 200)
    for port in scanResult:
        portResult.insert('', index, values=(port, "Open"))
        index = index + 1
    portStatusLabel.configure(text='•IDLE', fg='green')
    portStatusLabel.update()
        

def osScan():
    osStatusLabel.configure(text='•Scanning', fg='red')
    osStatusLabel.update()
    ipAddr = osInputAddr.get()
    index = 0
    treeViewFree(osResult)
    scanResult = nmap_os_scan(ipAddr)
    for os in scanResult:
        osResult.insert('', index, values=(os[0], os[1]))
        index = index + 1
    osStatusLabel.configure(text='•IDLE', fg='green')
    osStatusLabel.update()
    

def ms17_010_scan():
    # Status Sign Busy
    ms17_010_StatusLabel.configure(text='•Checking', fg='red')
    ms17_010_StatusLabel.update()
    # Input
    ipAddr = ms17_010_InputAddr.get()
    # Reset Table
    treeViewFree(ms17_010_Result)
    # Check
    checkResult = ms17_010_checker.check(ipAddr, 445, 5000)
    ms17_010_Result.insert('', 0, values=(ipAddr, checkResult))
    # Status Sign IDLE
    ms17_010_StatusLabel.configure(text='•IDLE', fg='green')
    ms17_010_StatusLabel.update()


if __name__ == "__main__":
    # tkinter init
    newWindows = Tk()
    newWindows.title('Simple Scanner V0.2')
    # ------------------------------------Windows--------------------------------
    # Windows Scale Settings
    newWindows.resizable(False, False)
    winWidth = 600
    winHeight = 500
    # Get Screen Resolution
    screenWidth = newWindows.winfo_screenwidth()
    screenHeight = newWindows.winfo_screenheight()
    # Compute Center Position
    x = int((screenWidth - winWidth) / 2)
    y = int((screenHeight - winHeight) / 2)
    # Main windows position
    newWindows.geometry("%sx%s+%s+%s" % (winWidth, winHeight, x, y))

    # ----------------------------------Frames-----------------------------------
    frameList = []

    welcomeFrame = Frame(newWindows)
    frameList.append(welcomeFrame)

    yieldScannerFrame = Frame(newWindows)
    frameList.append(yieldScannerFrame)

    portScannerFrame = Frame(newWindows)
    frameList.append(portScannerFrame)

    osScannerFrame = Frame(newWindows)
    frameList.append(osScannerFrame)

    ms17_010_checker_frame = Frame(newWindows)
    frameList.append(ms17_010_checker_frame)

    for frame in frameList:
        frame.grid(row=0, column=0, sticky='nwes')

    # ------------------------------------Menu-----------------------------------
    menubar = Menu(newWindows)
    scanner_menu = Menu(menubar, tearoff=False)
    scanner_menu.add_command(label="网段主机扫描", command=yieldScannerFrame.tkraise)
    scanner_menu.add_command(label="主机端口扫描", command=portScannerFrame.tkraise)
    scanner_menu.add_command(label="主机系统分析", command=osScannerFrame.tkraise)
    menubar.add_cascade(label="网络扫描", menu=scanner_menu)
    poc_menu = Menu(menubar, tearoff=False)
    poc_menu.add_command(label="MS17-010:SMB远程溢出", command=ms17_010_checker_frame.tkraise)
    menubar.add_cascade(label="漏洞检测", menu=poc_menu)

    newWindows.config(menu=menubar)

    # ----------------------------------Frame：网段主机扫描-----------------------------------
    # 标题
    yieldStatusLabel = Label(yieldScannerFrame, text='•IDLE', fg='green')
    yieldFrameLabel = Label(yieldScannerFrame, text='网段存活主机扫描', font=('Times New Roman', 25))
    # 网段或者主机IP输入
    yieldInputLabel = Label(yieldScannerFrame, text="输入待扫描网段或主机", font=('Times New Roman', 15))
    yieldInputAddr = Entry(yieldScannerFrame, show=None)
    # 扫描键
    yieldScanButton = Button(yieldScannerFrame, text="Scan", command=pingScan)
    # 结果表
    yieldOutputLabel = Label(yieldScannerFrame, text="扫描结果", font=('Times New Roman', 15))
    yieldResult = ttk.Treeview(yieldScannerFrame, show="headings", columns=("Host", "Status"), height=18)
    yieldResult.column("Host", width=290)
    yieldResult.column("Status", width=290)
    yieldResult.heading("Host", text="Host")
    yieldResult.heading("Status", text="Status")
    # 滚动条
    yieldTableViewScroll = Scrollbar(yieldScannerFrame, orient='vertical', command=yieldResult.yview)
    yieldResult.configure(yscrollcommand=yieldTableViewScroll.set)

    yieldStatusLabel.place(x=5, y=5)
    yieldFrameLabel.grid(row=0)
    yieldInputLabel.grid(row=1)
    yieldInputAddr.grid(row=2, column=0)
    yieldScanButton.grid(row=3, column=0)
    yieldOutputLabel.grid(row=4, column=0, sticky='we')
    yieldResult.grid(row=5, column=0, sticky='we')
    yieldTableViewScroll.grid(row=5, column=1, sticky='ns')

    # ----------------------------------Frame：主机端口扫描-----------------------------------
    # 标题
    portStatusLabel = Label(portScannerFrame, text='•IDLE', fg='green')
    portFrameLabel = Label(portScannerFrame, text='端口扫描', font=('Times New Roman', 25))
    # 网段或者主机IP输入
    portInputLabel = Label(portScannerFrame, text="输入待扫描主机", font=('Times New Roman', 15))
    portInputAddr = Entry(portScannerFrame, show=None)
    # 扫描键
    portScanButton = Button(portScannerFrame, text="Scan", command=portScan)
    # 结果表
    portOutputLabel = Label(portScannerFrame, text="扫描结果", font=('Times New Roman', 15))
    portResult = ttk.Treeview(portScannerFrame, show="headings", columns=("Port", "Status"), height=18)
    portResult.column("Port", width=290)
    portResult.column("Status", width=290)
    portResult.heading("Port", text="Port")
    portResult.heading("Status", text="Status")
    # 滚动条
    portTableViewScroll = Scrollbar(portScannerFrame, orient='vertical', command=portResult.yview)
    portResult.configure(yscrollcommand=portTableViewScroll.set)

    portStatusLabel.place(x=5, y=5)
    portFrameLabel.grid(row=0)
    portInputLabel.grid(row=1)
    portInputAddr.grid(row=2, column=0)
    portScanButton.grid(row=3, column=0)
    portOutputLabel.grid(row=4, column=0, sticky='we')
    portResult.grid(row=5, column=0, sticky='we')
    portTableViewScroll.grid(row=5, column=1, sticky='ns')

    # ----------------------------------Frame：主机系统分析-----------------------------------
    # 标题
    osStatusLabel = Label(osScannerFrame, text='•IDLE', fg='green')
    osFrameLabel = Label(osScannerFrame, text='系统分析', font=('Times New Roman', 25))
    # 网段或者主机IP输入
    osInputLabel = Label(osScannerFrame, text="输入待分析主机", font=('Times New Roman', 15))
    osInputAddr = Entry(osScannerFrame, show=None)
    # 扫描键
    osScanButton = Button(osScannerFrame, text="Scan", command=osScan)
    # 结果表
    osOutputLabel = Label(osScannerFrame, text="分析结果", font=('Times New Roman', 15))
    osResult = ttk.Treeview(osScannerFrame, show="headings", columns=("OS", "Status"), height=18)
    osResult.column("OS", width=490)
    osResult.column("Status", width=90)
    osResult.heading("OS", text="Operating System")
    osResult.heading("Status", text="Credibility")
    # 滚动条
    osTableViewScroll = Scrollbar(osScannerFrame, orient='vertical', command=osResult.yview)
    osResult.configure(yscrollcommand=osTableViewScroll.set)

    osStatusLabel.place(x=5, y=5)
    osFrameLabel.grid(row=0)
    osInputLabel.grid(row=1)
    osInputAddr.grid(row=2, column=0)
    osScanButton.grid(row=3, column=0)
    osOutputLabel.grid(row=4, column=0, sticky='we')
    osResult.grid(row=5, column=0, sticky='we')
    osTableViewScroll.grid(row=5, column=1, sticky='ns')

    # ----------------------------------Frame：MS17_010 PoC-----------------------------------
    # 标题
    ms17_010_StatusLabel = Label(ms17_010_checker_frame, text='•IDLE', fg='green')
    ms17_010_FrameLabel = Label(ms17_010_checker_frame, text='MS17-010 PoC', font=('Times New Roman', 25))
    # 网段或者主机IP输入
    ms17_010_InputLabel = Label(ms17_010_checker_frame, text="输入待分析主机", font=('Times New Roman', 15))
    ms17_010_InputAddr = Entry(ms17_010_checker_frame, show=None)
    # 扫描键
    ms17_010_ScanButton = Button(ms17_010_checker_frame, text="Check", command=ms17_010_scan)
    # 结果表
    ms17_010_OutputLabel = Label(ms17_010_checker_frame, text="分析结果", font=('Times New Roman', 15))
    ms17_010_Result = ttk.Treeview(ms17_010_checker_frame, show="headings", columns=("Host", "Status"), height=2)
    ms17_010_Result.column("Host", width=290)
    ms17_010_Result.column("Status", width=290)
    ms17_010_Result.heading("Host", text="Host")
    ms17_010_Result.heading("Status", text="Status")
    # 漏洞信息
    ms17_010_InfoLabel = Label(ms17_010_checker_frame, text="漏洞信息", font=('Times New Roman', 15))
    ms17_010_Info = ttk.Treeview(ms17_010_checker_frame, show="headings", columns=("Host", "Status"), height=10)
    ms17_010_Info.column("Host", width=55)
    ms17_010_Info.column("Status", width=545)
    # Info
    PoCInfo = ms17_010_checker.get_plugin_info()
    index = 0
    for info in PoCInfo.items():
        ms17_010_Info.insert('', index, values=(info[0], info[1]))
        index = index + 1
    
    ms17_010_StatusLabel.place(x=5, y=5)
    ms17_010_FrameLabel.pack()
    ms17_010_InputLabel.pack()
    ms17_010_InputAddr.pack()
    ms17_010_ScanButton.pack()
    ms17_010_OutputLabel.pack()
    ms17_010_Result.pack(fill=X)
    ms17_010_InfoLabel.pack()
    ms17_010_Info.pack(fill=X)

    yieldScannerFrame.tkraise()
    newWindows.mainloop()
