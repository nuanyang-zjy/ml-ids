from django.db import models
from datetime import datetime

from django.utils.html import escape


class User(models.Model):
    username = models.CharField(max_length=50)
    nickname = models.CharField(max_length=50)
    password_hash = models.CharField(max_length=100)  # 密码
    password_salt = models.CharField(max_length=50)  # 密码干扰值
    status = models.IntegerField(default=1)  # 1正常 2禁用 6管理员 9删除
    create_at = models.DateTimeField(default=datetime.now)
    update_at = models.DateTimeField(default=datetime.now)
    is_authorize = models.BooleanField(default=False)
    is_change_file_type = models.BooleanField(default=False)  # 默认生成的文件类型为pdf

    def toDict(self):
        return {'id': self.id, 'username': self.username, 'nickname': self.nickname,
                'password_hash': self.password_hash, 'password_salt': self.password_salt, 'status': self.status,
                'create_at': self.create_at.strftime('%Y-%m-%d %H:%M:%S'),
                'update_at': self.update_at.strftime('%Y-%m-%d %H:%M:%S'),
                'is_authorize': self.is_authorize}

    class Meta:
        db_table = 'user'


class Task(models.Model):
    # 用于存储扫描任务
    task_id = models.UUIDField(unique=True)
    user = models.ForeignKey(User, on_delete=models.CASCADE, related_name='records')
    temp_result_file_path = models.CharField(max_length=255, null=True, blank=True)
    start_time = models.DateTimeField(null=False, blank=False)
    end_time = models.DateTimeField(null=True, blank=True)
    exec_time = models.CharField(null=True, blank=False, max_length=64)
    status = models.CharField(max_length=50, choices=[
        ('pending', '待处理'),
        ('processing', '处理中'),
        ('completed', '已完成'),
        ('failed', '失败'),
    ], default='pending')

    class Meta:
        db_table = 'records'


class TuningModels(models.Model):
    # 存储调优参数
    tuning_id = models.UUIDField(unique=True)
    user = models.ForeignKey(User, on_delete=models.CASCADE, related_name='tuning_model_user')
    tuning_model = models.CharField(max_length=64, null=False, blank=False, verbose_name='调优模型')
    start_time = models.DateTimeField(null=False, blank=False)
    end_time = models.DateTimeField(null=True, blank=True)
    
    # 随机森林参数
    n_estimators = models.IntegerField(null=True, blank=True)
    criterion = models.CharField(max_length=64, null=True, blank=True)
    max_depth = models.IntegerField(null=True, blank=True)
    max_features = models.CharField(max_length=64, null=True, blank=True)
    random_state = models.IntegerField(null=True, blank=True)
    
    # KNN参数
    n_neighbors = models.IntegerField(null=True, blank=True)
    p_measure = models.IntegerField(null=True, blank=True)
    weights = models.CharField(max_length=20, null=True, blank=True)
    
    # 结果
    accuracy = models.FloatField(null=True, verbose_name='准确率')
    precision = models.FloatField(null=True, verbose_name='精确率')
    recall = models.FloatField(null=True, verbose_name='召回率')
    f1_data = models.FloatField(null=True, verbose_name='F1总分')
    exec_time = models.CharField(null=True, blank=False, max_length=64)
    result_model_path = models.CharField(max_length=255, null=True, blank=True, verbose_name='模型路径')

    class Meta:
        db_table = 'tuning_models'


class IPAddressRule(models.Model):
    IP_RULE_CHOICES = [
        ('white', 'Whitelist'),
        ('black', 'Blacklist')
    ]

    ip_address = models.CharField(max_length=100, unique=True)
    rule_type = models.CharField(max_length=20, choices=IP_RULE_CHOICES)
    description = models.CharField(max_length=255, null=True, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)        # 更新数据会自动更新时间

    def __str__(self):
        return f"{self.rule_type}: {self.ip_address}"
