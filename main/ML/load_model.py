import os
import pickle

import numpy as np
import pandas as pd
import time

from tqdm import tqdm
from sklearn.ensemble import RandomForestClassifier
from sklearn.preprocessing import LabelEncoder, label_binarize
from ml_ids.settings import STATICFILES_DIRS
from main.models import TuningModels
from sklearn.metrics import accuracy_score
import traceback


class AttackForest:
    def __init__(self, pkl_path):
        self.pkl_path = pkl_path
        self.load_model()

    def get_test_data(self, filepath):
        # 读取数据并直接调整数据形状
        test_data = pd.read_csv(filepath, header=None).iloc[:, :-1]

        # 分割特征和标签
        x_test_list = test_data.iloc[:, :-1].values.tolist()
        y_test_list = test_data.iloc[:, -1].tolist()
        attack_type_mapping = {
            'normal': 'normal',
            # DoS攻击
            'back': 'dos', 'land': 'dos', 'neptune': 'dos', 'pod': 'dos', 'smurf': 'dos', 'teardrop': 'dos',
            'apache2': 'dos', 'udpstorm': 'dos', 'processtable': 'dos', 'mailbomb': 'dos', 'worm': 'dos',
            # Probe攻击
            'ipsweep': 'probe', 'nmap': 'probe', 'portsweep': 'probe', 'satan': 'probe',
            'mscan': 'probe', 'saint': 'probe',
            # U2R攻击
            'buffer_overflow': 'u2r', 'loadmodule': 'u2r', 'perl': 'u2r', 'rootkit': 'u2r',
            'xterm': 'u2r', 'ps': 'u2r', 'sqlattack': 'u2r',
            # R2L攻击
            'ftp_write': 'r2l', 'guess_passwd': 'r2l', 'imap': 'r2l', 'multihop': 'r2l',
            'phf': 'r2l', 'spy': 'r2l', 'warezclient': 'r2l', 'warezmaster': 'r2l',
            'xlock': 'r2l', 'xsnoop': 'r2l', 'sendmail': 'r2l', 'named': 'r2l',
            'snmpgetattack': 'r2l', 'httptunnel': 'r2l', 'snmpguess': 'r2l'
        }
        y_test_list = [attack_type_mapping[i] for i in y_test_list]
        return x_test_list, y_test_list

    def load_model(self):
        with open(self.pkl_path, 'rb') as f:
            object_list = pickle.load(f)

        # 检查 object_list 是否是 RandomForestClassifier 的实例
        if isinstance(object_list, RandomForestClassifier):
            self.forest = object_list
            # 如果没有提供预处理对象，则需要手动设置
            self.le_attack_type = LabelEncoder()
            self.le_protocol_type = LabelEncoder()
            self.le_service = LabelEncoder()
            self.le_flag = LabelEncoder()
        elif isinstance(object_list, list) and len(object_list) == 5:
            self.le_attack_type, self.le_protocol_type, self.le_service, self.le_flag, self.forest = object_list
        else:
            raise ValueError("Unsupported model format")

    def predict(self, data):
        input_data = self.preprocess_data(data)
        predict_result = self.forest.predict(input_data)
        predict_result_name = self.le_attack_type.inverse_transform(predict_result)
        return predict_result_name

    def preprocess_data(self, data):
        if self.le_protocol_type:
            data[1] = self.le_protocol_type.transform([data[1]])[0]
        if self.le_service:
            data[2] = self.le_service.transform([data[2]])[0]
        if self.le_flag:
            data[3] = self.le_flag.transform([data[3]])[0]
        dataS = pd.DataFrame(data).T
        columns = [
            'duration', 'protocol_type', 'service', 'flag', 'src_bytes', 'dst_bytes', 'land', 'wrong_fragment',
            'urgent',
            'hot', 'num_failed_logins', 'logged_in', 'num_compromised', 'root_shell', 'su_attempted', 'num_root',
            'num_file_creations', 'num_shells', 'num_access_files', 'num_outbound_cmds', 'is_host_login',
            'is_guest_login',
            'count', 'srv_count', 'serror_rate', 'srv_serror_rate', 'rerror_rate', 'srv_rerror_rate', 'same_srv_rate',
            'diff_srv_rate', 'srv_diff_host_rate', 'dst_host_count', 'dst_host_srv_count', 'dst_host_same_srv_rate',
            'dst_host_diff_srv_rate', 'dst_host_same_src_port_rate', 'dst_host_srv_diff_host_rate',
            'dst_host_serror_rate',
            'dst_host_srv_serror_rate', 'dst_host_rerror_rate', 'dst_host_srv_rerror_rate'
        ]
        dataS.columns = columns
        return dataS


def predict(model_path, test_set_path):
    pre_model = AttackForest(model_path)
    data_x, data_y = pre_model.get_test_data(test_set_path)

    data_sum = len(data_x)
    pred_list = []
    label_list = []
    for i in tqdm(range(len(data_x))):
        pred_list.append(pre_model.predict(data_x[i])[0])
        label_list.append(data_y[i])

    pred_label_list = [pred_list, label_list]
    current_time = time.strftime('%Y-%m-%d-%H-%M-%S', time.localtime(time.time()))
    save_path = os.path.join(STATICFILES_DIRS[0], 'results', 'pred_and_label_' + current_time + '.pkl')
    with open(save_path, 'wb') as model_file:
        pickle.dump(pred_label_list, model_file)
    return pred_list, label_list


def select_model(model_path):
    models = {
        'model1': os.path.join(STATICFILES_DIRS[0], 'ai_model', 'attack_forest_model.pkl'),
        'model2': os.path.join(STATICFILES_DIRS[0], 'ai_model', 'attack_forest_model.pkl'),
        'model3': os.path.join(STATICFILES_DIRS[0], 'ai_model', 'knn_model.pkl'),
    }
    
    if model_path.startswith('pkl'):
        # 如果是训练后的模型文件，直接从模型保存目录获取
        latest_knn = TuningModels.objects.filter(
            tuning_model='KNN Model'
        ).latest('end_time')
        if latest_knn and latest_knn.result_model_path:
            return latest_knn.result_model_path
    
    return models.get(model_path)


def predict_knn(model_path, test_path, le_protocol_type, le_service, le_flag):
    """KNN模型预测函数"""
    try:
        # 加载模型
        with open(model_path, 'rb') as f:
            knn_model = pickle.load(f)
        
        # 定义列名和攻击类型映射
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
            'duration', 'protocol_type', 'service', 'flag', 'src_bytes',
            'dst_bytes', 'wrong_fragment', 'urgent', 'hot', 'num_failed_logins',
            'logged_in', 'num_compromised', 'root_shell', 'su_attempted',
            'num_root', 'num_file_creations'
        ]
        
        # 将攻击类型映射为五大类
        attack_mapping = {
            'normal': 'normal',
            # DoS攻击
            'back': 'dos', 'land': 'dos', 'neptune': 'dos', 'pod': 'dos', 
            'smurf': 'dos', 'teardrop': 'dos', 'apache2': 'dos', 
            'udpstorm': 'dos', 'processtable': 'dos', 'mailbomb': 'dos',
            # Probe攻击
            'ipsweep': 'probe', 'nmap': 'probe', 'portsweep': 'probe', 
            'satan': 'probe', 'mscan': 'probe', 'saint': 'probe',
            # R2L攻击
            'ftp_write': 'r2l', 'guess_passwd': 'r2l', 'imap': 'r2l',
            'multihop': 'r2l', 'phf': 'r2l', 'spy': 'r2l', 'warezclient': 'r2l',
            'warezmaster': 'r2l', 'sendmail': 'r2l', 'named': 'r2l', 'snmpgetattack': 'r2l',
            'snmpguess': 'r2l', 'xlock': 'r2l', 'xsnoop': 'r2l', 'httptunnel': 'r2l',
            # U2R攻击
            'buffer_overflow': 'u2r', 'loadmodule': 'u2r', 'perl': 'u2r', 
            'rootkit': 'u2r', 'ps': 'u2r', 'sqlattack': 'u2r', 'xterm': 'u2r'
        }
        
        # 先将攻击类型映射为五大类
        test_data['attack_category'] = test_data['attack'].map(lambda x: attack_mapping.get(x, 'unknown'))
        y_test = test_data['attack_category'].tolist()
        
        # 分离特征
        X_test = test_data[selected_features].copy()
        
        try:
            # 处理分类特征
            categorical_columns = ['protocol_type', 'service', 'flag']
            for feature, encoder in [('protocol_type', le_protocol_type), 
                                   ('service', le_service), 
                                   ('flag', le_flag)]:
                unknown_values = set(X_test[feature]) - set(encoder.classes_)
                if unknown_values:
                    print(f"警告：在{feature}中发现未知值：{unknown_values}")
                    most_common = encoder.classes_[0]
                    X_test[feature] = X_test[feature].replace(list(unknown_values), most_common)
            
            # 转换分类特征
            for feature, encoder in [('protocol_type', le_protocol_type), 
                                   ('service', le_service), 
                                   ('flag', le_flag)]:
                X_test[feature] = encoder.transform(X_test[feature])
            
            # 确保所有特征为float类型
            X_test = X_test.astype(float)
            
            # 进行预测
            numeric_predictions = knn_model.predict(X_test)
            
            # 将数值预测结果映射为攻击类型
            attack_types = ['normal', 'dos', 'probe', 'r2l', 'u2r']
            predictions = [attack_types[int(p)] for p in numeric_predictions]
            
            print("预测标签示例:", predictions[:5])
            print("实际标签示例:", y_test[:5])
            print("唯一预测标签:", set(predictions))
            print("唯一实际标签:", set(y_test))
            
            # 计算准确率
            accuracy = accuracy_score(y_test, predictions)
            print(f"计算得到的准确率: {accuracy}")
            
            return predictions, y_test
            
        except Exception as e:
            print(f"特征处理或预测过程中出错: {str(e)}")
            print(f"详细错误信息: {traceback.format_exc()}")
            raise ValueError(f"预测失败: {str(e)}")
            
    except Exception as e:
        print(f"KNN预测过程中出错: {str(e)}")
        print(f"详细错误信息: {traceback.format_exc()}")
        raise ValueError(f"KNN预测失败: {str(e)}")
