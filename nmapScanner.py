import nmap

def nmap_os_scan(host):
    nm = nmap.PortScanner()
    ret = nm.scan(host, arguments='-O -Pn')
    retL = []
    # 分析扫描结果
    for host, result in ret['scan'].items():
        if result['status']['state'] == 'up':
            print('#' * 17 + 'Host:' + host + '#' * 17)
            print('-' * 20 + '操作系统猜测' + '-' * 20)
            for os in result['osmatch']:
                print('操作系统为：' + os['name'] + ' ' * 3 + '准确度为：' + os['accuracy'])
                retL.append((os['name'], os['accuracy']))
    return retL


def nmap_ping_scan(network_prefix):
    # 创建一个扫描实例
    nm = nmap.PortScanner()
    # 配置nmap参数
    ping_scan_raw_result = nm.scan(hosts=network_prefix, arguments='-sn')
    # 分析扫描结果，并放入主机清单
    host_list = [result['addresses']['ipv4'] for result in ping_scan_raw_result['scan'].values() if
                 result['status']['state'] == 'up']
    return host_list