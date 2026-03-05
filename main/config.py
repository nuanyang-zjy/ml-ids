PATTERN_LIST = [
    {'sql': ('SQL注入', '高危')},
    {'xss': ('XSS', '高危')},
    {'shell': ('远程命令执行', '高危')},
    {'serialize': ('反序列化', '高危')},
    {'dir_search': ('目录遍历', '低危')},
]


def get_risk_level(pattern):
    for item in PATTERN_LIST:
        if pattern in item:
            return item[pattern]
