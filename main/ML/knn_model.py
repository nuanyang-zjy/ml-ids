from sklearn.neighbors import KNeighborsClassifier
from sklearn.metrics import accuracy_score, precision_score, recall_score, f1_score
from sklearn.preprocessing import LabelBinarizer
import time
import numpy as np

class KNNModel:
    def __init__(self, n_neighbors=5, p=2, weights='uniform'):
        self.n_neighbors = n_neighbors
        self.p = p
        self.weights = weights
        self.model = KNeighborsClassifier(
            n_neighbors=n_neighbors,
            p=p,
            weights=weights,
            algorithm='auto',  # 自动选择最优算法
            n_jobs=-1  # 使用所有CPU核心
        )
        
    def train_and_evaluate(self, X_train, y_train, X_test, y_test):
        """训练模型并评估性能"""
        start_time = time.time()
        
        # 确保标签是正确的格式
        lb = LabelBinarizer()
        if len(np.unique(y_train)) == 2:
            y_train_bin = lb.fit_transform(y_train).ravel()
            y_test_bin = lb.transform(y_test).ravel()
        else:
            y_train_bin = y_train
            y_test_bin = y_test
        
        # 训练模型
        self.model.fit(X_train, y_train_bin)
        
        # 预测
        y_pred = self.model.predict(X_test)
        
        # 计算执行时间
        exec_time = time.time() - start_time
        
        # 计算性能指标
        metrics = {
            'accuracy': accuracy_score(y_test_bin, y_pred),
            'precision': precision_score(y_test_bin, y_pred, average='binary' if len(np.unique(y_test)) == 2 else 'weighted'),
            'recall': recall_score(y_test_bin, y_pred, average='binary' if len(np.unique(y_test)) == 2 else 'weighted'),
            'f1': f1_score(y_test_bin, y_pred, average='binary' if len(np.unique(y_test)) == 2 else 'weighted'),
            'exec_time': exec_time
        }
        
        # 添加详细的分类报告
        from sklearn.metrics import classification_report
        print("\nClassification Report:")
        print(classification_report(y_test_bin, y_pred))
        
        return metrics
    
    def get_neighbor_distances(self, X_test, n_samples=100):
        """获取测试样本的最近邻距离"""
        if n_samples > len(X_test):
            n_samples = len(X_test)
            
        # 随机选择样本
        indices = np.random.choice(len(X_test), n_samples, replace=False)
        X_samples = X_test[indices]
        
        # 计算距离
        distances, _ = self.model.kneighbors(X_samples)
        
        # 计算每个样本的平均距离
        avg_distances = distances.mean(axis=1)
        
        return {
            'sample_indices': indices.tolist(),
            'distances': avg_distances.tolist()
        }
    
    def get_model_info(self):
        """获取模型信息"""
        return {
            'n_neighbors': self.n_neighbors,
            'p': self.p,
            'weights': self.weights,
            'algorithm': self.model.algorithm,
            'metric': self.model.metric
        }
    
    def save_model(self, path):
        """保存模型"""
        import pickle
        with open(path, 'wb') as f:
            pickle.dump(self.model, f)
    
    @staticmethod
    def load_model(path):
        """加载模型"""
        import pickle
        with open(path, 'rb') as f:
            model = pickle.load(f)
        return model

def main_model_tuning_knn(n_neighbors, p_measure, weights, X_train, y_train, X_test, y_test):
    """主调优函数"""
    print(f"\nTraining KNN with parameters:")
    print(f"n_neighbors: {n_neighbors}")
    print(f"p_measure: {p_measure}")
    print(f"weights: {weights}")
    
    # 打印数据集信息
    print(f"\nTraining set shape: {X_train.shape}")
    print(f"Test set shape: {X_test.shape}")
    print(f"Number of classes in training set: {len(np.unique(y_train))}")
    
    # 创建模型实例
    knn = KNNModel(
        n_neighbors=n_neighbors,
        p=p_measure,
        weights=weights
    )
    
    # 训练并评估模型
    metrics = knn.train_and_evaluate(X_train, y_train, X_test, y_test)
    
    # 打印详细结果
    print("\nDetailed Results:")
    for metric, value in metrics.items():
        if metric != 'exec_time':
            print(f"{metric.capitalize()}: {value * 100:.2f}%")
    print(f"Execution Time: {metrics['exec_time']:.2f} seconds")
    
    # 保存模型
    import os
    model_dir = 'main/DL/models'
    os.makedirs(model_dir, exist_ok=True)
    model_path = os.path.join(model_dir, f'knn_model_{n_neighbors}_{p_measure}_{weights}.pkl')
    knn.save_model(model_path)
    
    return {
        'metrics': metrics,
        'model_info': knn.get_model_info(),
        'model_path': model_path
    }