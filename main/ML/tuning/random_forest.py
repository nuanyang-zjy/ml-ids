import os
import pickle
import time
import warnings
import pandas as pd
from sklearn.ensemble import RandomForestClassifier, VotingClassifier
from sklearn.metrics import accuracy_score, precision_score, recall_score, confusion_matrix, f1_score
from sklearn.preprocessing import StandardScaler, MinMaxScaler, LabelEncoder
import joblib

from ml_ids.settings import STATICFILES_DIRS

warnings.filterwarnings("ignore")


def prepare_datasets(train_file_path, test_file_path, label_encode_columns, feature_columns):
    # 设置列标签
    columns = [
        'duration',
        'protocol_type',
        'service',
        'flag',
        'src_bytes',
        'dst_bytes',
        'land',
        'wrong_fragment',
        'urgent',
        'hot',
        'num_failed_logins',
        'logged_in',
        'num_compromised',
        'root_shell',
        'su_attempted',
        'num_root',
        'num_file_creations',
        'num_shells',
        'num_access_files',
        'num_outbound_cmds',
        'is_host_login',
        'is_guest_login',
        'count',
        'srv_count',
        'serror_rate',
        'srv_serror_rate',
        'rerror_rate',
        'srv_rerror_rate',
        'same_srv_rate',
        'diff_srv_rate',
        'srv_diff_host_rate',
        'dst_host_count',
        'dst_host_srv_count',
        'dst_host_same_srv_rate',
        'dst_host_diff_srv_rate',
        'dst_host_same_src_port_rate',
        'dst_host_srv_diff_host_rate',
        'dst_host_serror_rate',
        'dst_host_srv_serror_rate',
        'dst_host_rerror_rate',
        'dst_host_srv_rerror_rate',
        'attack',
        'level'
    ]
    df_train = pd.read_csv(train_file_path, header=None, names=columns)
    df_test = pd.read_csv(test_file_path, header=None, names=columns)
    df_train["binary_attack"] = df_train.attack.map(lambda a: "normal" if a == 'normal' else "abnormal")
    df_test["binary_attack"] = df_test.attack.map(lambda a: "normal" if a == 'normal' else "abnormal")
    df_train.drop('attack', axis=1, inplace=True)
    df_test.drop('attack', axis=1, inplace=True)
    le = LabelEncoder()  # 创建标签编码器实例
    for x in label_encode_columns:
        df_train[x] = le.fit_transform(df_train[x])
        df_test[x] = le.fit_transform(df_test[x])

    # 分割训练集的特征和标签
    x_train = df_train.drop('binary_attack', axis=1)
    y_train = df_train["binary_attack"]

    # 分割测试集的特征和标签
    x_test = df_test.drop('binary_attack', axis=1)
    y_test = df_test["binary_attack"]

    x_train = x_train[feature_columns]
    x_test = x_test[feature_columns]

    scaler = MinMaxScaler()

    # 对训练集数据进行标准化处理，转换后的数据范围在[0, 1]之间
    x_train = scaler.fit_transform(x_train)

    # 对测试集数据进行标准化处理，同样的转换确保训练集和测试集的特征缩放一致
    x_test = scaler.fit_transform(x_test)

    return x_train, x_test, y_train, y_test


clm = ['protocol_type', 'service', 'flag', 'binary_attack']
col = ['service', 'flag', 'src_bytes', 'dst_bytes', 'logged_in', 'count', 'serror_rate', 'srv_serror_rate',
       'same_srv_rate', 'diff_srv_rate', 'srv_diff_host_rate', 'dst_host_count', 'dst_host_srv_count',
       'dst_host_same_srv_rate', 'dst_host_diff_srv_rate', 'dst_host_same_src_port_rate', 'dst_host_srv_diff_host_rate',
       'dst_host_serror_rate', 'dst_host_srv_serror_rate', 'level'
       ]

train_file_path = os.path.join(STATICFILES_DIRS[0], 'data_set', 'KDDTrain', 'KDDTrain+.txt')
test_file_path = os.path.join(STATICFILES_DIRS[0], 'data_set', 'KDDTest', 'KDDTest+.txt')
x1_train, x1_test, y1_train, y1_test = prepare_datasets(train_file_path, test_file_path, clm, col)


def main_model_tuning(
        n_estimators: int,
        criterion: str,
        max_depth: int,
        max_features: str,
        random_state: int,
        x_train=x1_train, x_test=x1_test, y_train=y1_train, y_test=y1_test):
    models = {
        'Random Forest':
            RandomForestClassifier(
                n_estimators=n_estimators,
                criterion=criterion,
                max_depth=max_depth,
                max_features=max_features,
                random_state=random_state
            )
    }

    # 初始化随机森林模型
    for key in models.keys():
        models[key].fit(x_train, y_train)   # 对当前循环到的模型进行训练

    # 保存模型
    current_time = time.strftime('%Y-%m-%d-%H-%M-%S', time.localtime(time.time()))
    try:
        model_file_path = os.path.join(STATICFILES_DIRS[0], 'tuning_model', 'pred_and_label_' + current_time + '.pkl')
        with open(model_file_path, 'wb') as model_file:
            pickle.dump(models['Random Forest'], model_file)
    except FileNotFoundError:
        return
    except Exception as e:
        print(f"模型保存失败: {e}")
        # 处理其他可能的异常
        return
    accuracy, precision, recall = {}, {}, {}

    for key in models.keys():
        # 对当前循环到的模型进行训练
        models[key].fit(x_train, y_train)
        # 使用训练好的模型对测试集进行预测
        predictions = models[key].predict(x_test)
        # 计算并存储当前模型的准确率、精确度和召回率
        accuracy[key] = accuracy_score(predictions, y_test)
        precision[key] = precision_score(predictions, y_test)
        recall[key] = recall_score(predictions, y_test)
        f1 = f1_score(predictions, y_test, average='macro')
    return list(accuracy.values()), list(precision.values()), list(recall.values()), f1, model_file_path

