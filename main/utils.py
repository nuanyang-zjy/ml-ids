import re
from main import config


def http_attack(url):
    # sql注入, xss 远程命令执行，ddos，缓冲区溢出漏洞， 目录遍历， 未授权访问， 暴力破解...
    # sql注入漏洞利用特征
    pattern_sql = re.compile(
        r'(\=.*\-\-)'
        r'|(\w+(%|\$|#)\w+)'
        r'|(.*\|\|.*)'
        r'|(?:\s+(and|or)\s+)'
        r'|(\b(select|update|union|and|or|delete|insert|trancate|char|into|'
        r'substr|ascii|declare|exec)\b)'
        r'|(\b(count|master|drop|execute)\b)',
        re.IGNORECASE)
    """
    http://127.0.0.1/test.php?id=1 and (select count(*) from sysobjects)>0 and 1=1

    """
    # 跨站脚本攻击漏洞特征
    pattern_xss = re.compile(
        r'(<.*>)'  # 匹配尖括号包围的内容
        r'|(\{|\})'  # 匹配左右大括号
        r'|"|>|<'  # 匹配引号以及尖括号
        r'|(script)'  # 匹配 'script' 关键字
        r'|(onerror)'  # 匹配 'onerror' 关键字
        r'|(onload)'  # 匹配 'onload' 关键字
        r'|(javascript:)'  # 匹配 'javascript:' 关键字
        r'|(alert\()'  # 匹配 'alert()' 关键字
        r'|(document\.)'  # 匹配 'document.' 关键字
        r'|(window\.)'  # 匹配 'window.' 关键字
        r'|(location\.)'  # 匹配 'location.' 关键字
        r'|(eval\()'  # 匹配 'eval()' 关键字
        r'|(setTimeout\()'  # 匹配 'setTimeout()' 关键字
        r'|(setInterval\()',  # 匹配 'setInterval()' 关键字
        re.IGNORECASE)
    # 命令执行漏洞特征
    pattern_shell = re.compile(
        r"(eval)"
        r"|(ping)"
        r"|(echo)"
        r"|(cmd)"
        r"|(/etc/).+"
        r"|(whoami)"
        r"|(ipconfig)"
        r"|(/bin/).+"
        r"|(array_map)"
        r"|(phpinfo)"
        r"|(\$_).+"
        r"|(var_dump)"
        r"|(call_user_func)"
        r"|(/usr/).+"
        r"|(c:/).+", re.IGNORECASE)
    # 目录遍历特征
    pattern_dir_search = re.compile(
        r'(/robots.txt)'  # 匹配 robots.txt 文件
        r'|\.\./'  # 匹配 ../ 表示上级目录
        r'|\w*.conf'  # 匹配以 .conf 结尾的文件
        r'|(/admin)'  # 匹配 /admin 目录
        r'|(/etc/passwd)'  # 匹配 /etc/passwd 文件
        r'|(/etc/shadow)'  # 匹配 /etc/shadow 文件
        r'|(/etc/hosts)'  # 匹配 /etc/hosts 文件
        r'|(/etc/group)'  # 匹配 /etc/group 文件
        r'|(/proc/version)'  # 匹配 /proc/version 文件
        r'|(/proc/self/environ)'  # 匹配 /proc/self/environ 文件
        r'|(/proc/cmdline)'  # 匹配 /proc/cmdline 文件
        r'|(/proc/mounts)'  # 匹配 /proc/mounts 文件
        r'|(/proc/net/route)',  # 匹配 /proc/net/route 文件
        re.IGNORECASE)
    # 反序列化漏洞特征
    pattern_serialize = re.compile(
        r"(‘/[oc]:\d+:/i’, \$var)"  # 匹配指定格式的反序列化字符串
        r'|(unserialize\()'  # 匹配 'unserialize()' 函数
        r'|(base64_decode\()'  # 匹配 'base64_decode()' 函数
        r'|(json_decode\()'  # 匹配 'json_decode()' 函数
        r'|(msgpack_unpack\()'  # 匹配 'msgpack_unpack()' 函数
        r'|(pickle.loads\()'  # 匹配 'pickle.loads()' 函数
        r'|(xmlrpc_decode\()',  # 匹配 'xmlrpc_decode()' 函数
        re.IGNORECASE)
    pattern_url_file_inclusion = re.compile(
        r'(\binclude\b)'
        r'|(\brequire\b)'
        r'|(\brequire_once\b)'
        r'|(\binclude_once\b)',  # 匹配 URL 中的文件包含漏洞关键词
        re.IGNORECASE
    )
    patterns = {
        'sql': pattern_sql,
        'xss': pattern_xss,
        'shell': pattern_shell,
        'dir_search': pattern_dir_search,
        'serialize': pattern_serialize
    }
    for pattern_name, pattern in patterns.items():
        match = pattern.search(url)
        if match is not None:
            attack, threat = config.get_risk_level(pattern_name)
            attack_name = pattern_name
            feature = match[0]
            break
        else:
            attack = threat = feature = attack_name = None

    return (attack, attack_name), threat, feature