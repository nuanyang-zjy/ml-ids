from django.urls import path
from . import user

from main import views

urlpatterns = [
    # 基础服务
    path('', views.login, name="myadmin_login"),
    path('login', views.login, name="myadmin_login2"),
    path('dologin', views.dologin, name="myadmin_dologin"),
    path('logout', views.logout_view, name="myadmin_logout"),
    path('register', views.register, name="myadmin_register"),
    path('doregister', views.doregister, name="myadmin_doregister"),
    path('forgot_pd', views.forgot_pd, name="forgot_pd"),
    # 管理员
    path('user/<int:pIndex>', user.index, name="myadmin_user_index"),
    path('user/insert', user.insert, name="myadmin_user_insert"),
    path('user/delete/<int:uid>', user.delete, name="myadmin_user_delete"),
    path('user/edit/<int:uid>', user.edit, name="myadmin_user_edit"),
    path('user/update/<int:uid>', user.update, name="myadmin_user_update"),

    # 模型展示
    path('index', views.index, name="ids_index"),
    path('dataset', views.dataset, name="ids_dataset"),
    path('screen', views.screen, name="ids_screen"),
    path('model', views.model_info, name="ids_model"),

    # 模型测试集
    path('dataset_res', views.dataset_result, name="ids_dataset_result"),

    # 模型使用
    path('predict_exec', views.predict_exec, name="predict_exec"),
    path('predict_echarts', views.predict_res, name="predict_echarts"),

    # 模型调优
    path('model_tuning', views.model_tuning, name="ids_model_tuning"),
    path('tuning_random_forest', views.model_tuning_random_forest, name="tuning_random_forest"),
    path('reset_parameter_random_forest', views.reset_parameter_random_forest, name='reset_parameter_random_forest'),
    path('tuning_knn', views.model_tuning_knn, name="tuning_knn"),
    path('reset_parameter_knn_model', views.reset_parameter_knn_model, name='reset_parameter_knn_model'),

    # 本地pcap包自测
    path('upload_pcapng', views.upload_pcapng, name='upload_pcapng'),

    # IP规则管理
    path('ip-rules/', views.ip_rule_list, name='ip_rule_list'),
    path('ip-rules/add/', views.add_ip_rule, name='add_ip_rule'),
    path('ip-rules/delete/<int:rule_id>/', views.delete_ip_rule, name='delete_ip_rule'),


]