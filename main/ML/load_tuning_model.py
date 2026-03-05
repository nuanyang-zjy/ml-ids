import os
import pickle
import pandas as pd
from sklearn.preprocessing import MinMaxScaler, LabelEncoder
from sklearn.metrics import accuracy_score, precision_score, recall_score, f1_score


# 加载模型
def load_model(model_file_path):
    with open(model_file_path, 'rb') as model_file:
        model = pickle.load(model_file)
    return model


# 准备测试数据
def prepare_test_data(test_file_path, label_encode_columns, feature_columns, le_protocol_type, le_service, le_flag):
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

    df_test = pd.read_csv(test_file_path, header=None, names=columns)

    # 标签编码
    df_test['protocol_type'] = le_protocol_type.transform(df_test['protocol_type'])
    df_test['service'] = le_service.transform(df_test['service'])
    df_test['flag'] = le_flag.transform(df_test['flag'])

    df_test["binary_attack"] = df_test.attack.map(lambda a: "normal" if a == 'normal' else "abnormal")
    df_test.drop('attack', axis=1, inplace=True)

    # 提取特征
    x_test = df_test[feature_columns]

    # 标准化
    scaler = MinMaxScaler()
    x_test = scaler.fit_transform(x_test)  # 使用训练集的缩放参数

    return x_test, df_test["binary_attack"]


# clm，需要进行标签编码的特征列
"""
protocol_type：协议类型（如 TCP、UDP 等）。
service：服务类型（如 HTTP、FTP 等）。
flag：连接状态的标志。
binary_attack：二元分类标签，表示是否为攻击（尽管通常在训练模型时不直接使用该列进行编码）
"""
clm = ['protocol_type', 'service', 'flag', 'binary_attack']

# clo， 模型训练的特征列
col = ['service', 'flag', 'src_bytes', 'dst_bytes', 'logged_in', 'count', 'serror_rate',
       'srv_serror_rate', 'same_srv_rate', 'diff_srv_rate', 'srv_diff_host_rate',
       'dst_host_count', 'dst_host_srv_count', 'dst_host_same_srv_rate',
       'dst_host_diff_srv_rate', 'dst_host_same_src_port_rate',
       'dst_host_srv_diff_host_rate', 'dst_host_serror_rate',
       'dst_host_srv_serror_rate', 'level']


def tuning_random_forest(model_path, test_path, le_protocol_type, le_service, le_flag):
    """随机森林模型预测函数"""
    try:
        # 加载模型
        with open(model_path, 'rb') as f:
            rf_model = pickle.load(f)
        
        # 定义列名
        columns = [
            'duration', 'protocol_type', 'service', 'flag', 'src_bytes',
            'dst_bytes', 'land', 'wrong_fragment', 'urgent', 'hot',
            'num_failed_logins', 'logged_in', 'num_compromised', 'root_shell',
            'su_attempted', 'num_root', 'num_file_creations', 'num_shells',
            'num_access_files', 'num_outbound_cmds', 'is_host_login',
            'is_guest_login', 'count', 'srv_count', 'serror_rate',
            'srv_serror_rate', 'rerror_rate', 'srv_rerror_rate',
            'same_srv_rate', 'diff_srv_rate', 'srv_diff_host_rate',
            'dst_host_count', 'dst_host_srv_count', 'dst_host_same_srv_rate',
            'dst_host_diff_srv_rate', 'dst_host_same_src_port_rate',
            'dst_host_srv_diff_host_rate', 'dst_host_serror_rate',
            'dst_host_srv_serror_rate', 'dst_host_rerror_rate',
            'dst_host_srv_rerror_rate', 'attack', 'level'
        ]
        
        # 读取测试数据
        test_data = pd.read_csv(test_path, header=None, names=columns)
        
        # 选择与训练时相同的特征
        selected_features = [
            'service', 'flag', 'src_bytes', 'dst_bytes', 'logged_in',
            'count', 'serror_rate', 'srv_serror_rate', 'same_srv_rate',
            'diff_srv_rate', 'srv_diff_host_rate', 'dst_host_count',
            'dst_host_srv_count', 'dst_host_same_srv_rate',
            'dst_host_diff_srv_rate', 'dst_host_same_src_port_rate',
            'dst_host_srv_diff_host_rate', 'dst_host_serror_rate',
            'dst_host_srv_serror_rate', 'level'
        ]
        
        # 将攻击类型映射为二进制标签（normal/abnormal）
        test_data['binary_attack'] = test_data.attack.map(
            lambda a: "normal" if a == 'normal' else "abnormal"
        )
        
        # 分离特征和标签，只选择需要的特征
        X_test = test_data[selected_features].copy()
        y_test = test_data['binary_attack'].tolist()
        
        # 转换分类特征
        categorical_features = ['service', 'flag']
        for feature in categorical_features:
            if feature == 'service':
                X_test[feature] = le_service.transform(X_test[feature])
            elif feature == 'flag':
                X_test[feature] = le_flag.transform(X_test[feature])
        
        # 确保所有特征为数值类型
        X_test = X_test.astype(float)
        
        print(f"特征数量: {X_test.shape[1]}")
        print(f"使用的特征: {X_test.columns.tolist()}")
        
        # 进行预测
        predictions_numeric = rf_model.predict(X_test)
        
        # 将数值预测结果转换为字符串标签
        predictions = ["normal" if pred == 1 else "abnormal" for pred in predictions_numeric]
        
        # 计算性能指标
        accuracy = accuracy_score(y_test, predictions)
        precision = precision_score(y_test, predictions, pos_label="abnormal")
        recall = recall_score(y_test, predictions, pos_label="abnormal")
        f1 = f1_score(y_test, predictions, pos_label="abnormal")
        
        print("预测完成：", len(predictions), "条记录")
        return accuracy, precision, recall, f1, predictions, y_test
        
    except Exception as e:
        print(f"随机森林预测过程中出错: {str(e)}")
        print(f"错误类型: {type(e)}")
        import traceback
        print(f"详细错误信息: {traceback.format_exc()}")
        raise ValueError(f"随机森林预测失败: {str(e)}")

