import pandas as pd
import numpy as np
from sklearn.preprocessing import LabelEncoder, MinMaxScaler
from sklearn.model_selection import train_test_split


def load_and_process_data(train_file_path, test_file_path=None):
    """加载和处理数据"""
    # 定义列名
    columns = [
        'duration', 'protocol_type', 'service', 'flag', 'src_bytes', 'dst_bytes',
        'land', 'wrong_fragment', 'urgent', 'hot', 'num_failed_logins', 'logged_in',
        'num_compromised', 'root_shell', 'su_attempted', 'num_root', 'num_file_creations',
        'num_shells', 'num_access_files', 'num_outbound_cmds', 'is_host_login',
        'is_guest_login', 'count', 'srv_count', 'serror_rate', 'srv_serror_rate',
        'rerror_rate', 'srv_rerror_rate', 'same_srv_rate', 'diff_srv_rate',
        'srv_diff_host_rate', 'dst_host_count', 'dst_host_srv_count',
        'dst_host_same_srv_rate', 'dst_host_diff_srv_rate', 'dst_host_same_src_port_rate',
        'dst_host_srv_diff_host_rate', 'dst_host_serror_rate', 'dst_host_srv_serror_rate',
        'dst_host_rerror_rate', 'dst_host_srv_rerror_rate', 'attack', 'level'
    ]

    # 加载训练数据
    df_train = pd.read_csv(train_file_path, header=None, names=columns)

    # 如果提供了测试文件路径，也加载测试数据
    if test_file_path:
        df_test = pd.read_csv(test_file_path, header=None, names=columns)

    # 创建标签编码器
    le_protocol_type = LabelEncoder()
    le_service = LabelEncoder()
    le_flag = LabelEncoder()

    # 对训练数据进行标签编码
    df_train['protocol_type'] = le_protocol_type.fit_transform(df_train['protocol_type'])
    df_train['service'] = le_service.fit_transform(df_train['service'])
    df_train['flag'] = le_flag.fit_transform(df_train['flag'])

    # 二元化攻击标签
    df_train["binary_attack"] = df_train.attack.map(lambda a: 0 if a == 'normal' else 1)

    # 选择特征列
    feature_columns = [
        'duration', 'protocol_type', 'service', 'flag', 'src_bytes',
        'dst_bytes', 'logged_in', 'count', 'serror_rate',
        'srv_serror_rate', 'same_srv_rate', 'diff_srv_rate',
        'dst_host_count', 'dst_host_srv_count',
        'dst_host_same_srv_rate', 'dst_host_diff_srv_rate'
    ]

    # 提取特征和标签
    X = df_train[feature_columns]
    y = df_train['binary_attack']

    # 标准化特征
    scaler = MinMaxScaler()
    X = scaler.fit_transform(X)

    # 分割训练集和验证集
    X_train, X_val, y_train, y_val = train_test_split(
        X, y, test_size=0.2, random_state=42
    )

    # 如果有测试数据，也进行相同的处理
    if test_file_path:
        df_test['protocol_type'] = le_protocol_type.transform(df_test['protocol_type'])
        df_test['service'] = le_service.transform(df_test['service'])
        df_test['flag'] = le_flag.transform(df_test['flag'])
        df_test["binary_attack"] = df_test.attack.map(lambda a: 0 if a == 'normal' else 1)

        X_test = df_test[feature_columns]
        X_test = scaler.transform(X_test)
        y_test = df_test['binary_attack']
    else:
        X_test, y_test = None, None

    return {
        'X_train': X_train,
        'X_val': X_val,
        'X_test': X_test,
        'y_train': y_train,
        'y_val': y_val,
        'y_test': y_test,
        'le_protocol_type': le_protocol_type,
        'le_service': le_service,
        'le_flag': le_flag,
        'scaler': scaler,
        'feature_columns': feature_columns
    }


def save_processed_data(data_dict, save_dir='main/ML/models/'):
    """保存处理后的数据和编码器"""
    import os
    import pickle

    # 确保目录存在
    os.makedirs(save_dir, exist_ok=True)

    # 保存数据和编码器
    for key, value in data_dict.items():
        if value is not None:  # 只保存非空值
            with open(os.path.join(save_dir, f'{key}.pkl'), 'wb') as f:
                pickle.dump(value, f)


def load_processed_data(load_dir='main/ML/models/'):
    """加载处理后的数据和编码器"""
    import os
    import pickle

    data_dict = {}
    for file in os.listdir(load_dir):
        if file.endswith('.pkl'):
            key = file[:-4]  # 移除.pkl后缀
            with open(os.path.join(load_dir, file), 'rb') as f:
                data_dict[key] = pickle.load(f)

    return data_dict
