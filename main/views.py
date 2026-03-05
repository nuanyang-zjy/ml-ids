import hashlib
import json
import os
import random
import tempfile
import time

import matplotlib.pyplot as plt
from collections import Counter
from datetime import datetime, timedelta

import pandas as pd
from django.contrib.auth import logout
from django.http import HttpResponseRedirect, HttpResponse, JsonResponse
from django.shortcuts import render, redirect
from django.urls import reverse
from django.utils import timezone
from django.views.decorators.http import require_http_methods
from django.core.files.storage import default_storage
from django.contrib import messages

from pyecharts.charts import Radar, Bar3D, Scatter3D, Pie, Bar, Line
from pyecharts import options as opts
from sklearn.metrics import accuracy_score, precision_score, recall_score, f1_score
from sklearn.preprocessing import label_binarize, LabelEncoder
from pyecharts.globals import ThemeType

from main.ML.load_tuning_model import tuning_random_forest
from main.forms import CustomCaptchaForm
from main.models import User, Task, TuningModels, IPAddressRule
from main.firewall import FirewallManager

from main.ML.tuning.random_forest import main_model_tuning
from main.ML.load_model import predict, select_model, predict_knn
from main.tests import generate_task_id
from ml_ids.settings import STATICFILES_DIRS
from main.ML.knn_model import main_model_tuning_knn
from main.ML.data_processor import load_and_process_data, save_processed_data, load_processed_data
from main.utils import http_attack

from scapy.all import rdpcap
from scapy.layers.inet import IP, TCP, UDP
from scapy.layers.http import HTTPRequest
from collections import defaultdict


def initialize_data():
    """初始化数据处理"""
    train_file = 'main/ML/data/KDDTrain+.txt'
    test_file = 'main/ML/data/KDDTest+.txt'

    # 检查是否已经处理过数据
    if not os.path.exists('main/ML/models/X_train.pkl'):
        # 处理数据
        data_dict = load_and_process_data(train_file, test_file)
        # 保存处理后的数据
        save_processed_data(data_dict)

    # 加载处理后的数据
    return load_processed_data()


processed_data = None


def get_processed_data():
    """获取处理后的数据，如果还没初始化则进行初始化"""
    global processed_data
    if processed_data is None:
        processed_data = initialize_data()
    return processed_data


def login(request):
    captcha_form = CustomCaptchaForm()
    context = {
        "captcha_form": captcha_form,
    }
    return render(request, 'login.html', context)


def dologin(request):
    captcha_form = CustomCaptchaForm()
    try:
        user = User.objects.get(username=request.POST['username'])
        print(user.toDict())
        if user.status == 1:
            import hashlib
            md5 = hashlib.md5()
            s = request.POST['pass'] + user.password_salt
            md5.update(s.encode('utf-8'))
            # 新增验证码
            captcha_form = CustomCaptchaForm(request.POST)
            if captcha_form.is_valid():
                # print(captcha_form.cleaned_data)
                if user.password_hash == md5.hexdigest():
                    request.session['is_login'] = True
                    request.session['login_user'] = user.toDict()

                    # print("用户登录")
                    # print(request.session['login_user'])
                    return redirect('/index')
                else:
                    context = {
                        "captcha_form": captcha_form,
                        "info": '账号或密码错误'
                    }
                    messages.error(request, '账号或密码错误')
                    return render(request, 'login.html', context)
            else:
                context = {
                    "captcha_form": captcha_form,
                    "error": '验证码错误'
                }
                messages.error(request, '验证码错误')
                return render(request, 'login.html', context)
        if user.status == 6:
            import hashlib
            md5 = hashlib.md5()
            s = request.POST['pass'] + user.password_salt
            md5.update(s.encode('utf-8'))
            captcha_form = CustomCaptchaForm(request.POST)
            if captcha_form.is_valid():
                print("验证码正确")
                if user.password_hash == md5.hexdigest():
                    request.session['is_login'] = True
                    request.session['adminuser'] = user.toDict()
                    return redirect(reverse("myadmin_user_index", args=(1,)))
                else:
                    context = {
                        "captcha_form": captcha_form,
                        "info": '密码错误'
                    }
                    messages.error(request, '账号或密码错误')
                    return render(request, 'login.html', context)
        else:
            context = {
                "captcha_form": captcha_form,
                "info": '账号无权限'
            }
            messages.error(request, '账号无权限')
    except Exception as e:
        print("报错为", e)
        context = {
            "captcha_form": captcha_form,
            "info": '账号或密码错误'
        }
        messages.error(request, '账号或密码错误')
    context = {
        "captcha_form": captcha_form,
        "info": '账号或密码错误'
    }
    messages.error(request, '账号或密码错误')
    return render(request, 'login.html', context)


def logout_view(request):
    logout(request)  # 清除当前用户所有session
    print("用户session", request.session.get('is_login'))
    return HttpResponseRedirect('login')


def register(request):
    return render(request, 'register.html')


def doregister(request):
    captcha_form = CustomCaptchaForm()
    username = request.POST['username']

    # 检查用户名是否已存在
    if User.objects.filter(username=username).exists():
        # 用户名已存在，返回错误信息或重定向到适当的页面
        error_message = "该用户名已被注册，请选择其他用户名。"
        context = {
            "captcha_form": captcha_form,
            "error": error_message,
        }
        return render(request, 'register.html', context)

    import hashlib, random
    md5 = hashlib.md5()
    n = random.randint(100000, 999999)
    s = request.POST['pass'] + str(n)
    md5.update(s.encode('utf-8'))

    ob = User()
    ob.username = username
    ob.password_hash = md5.hexdigest()
    ob.password_salt = n
    ob.status = 1
    ob.create_at = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    ob.update_at = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    ob.save()

    context = {
        "captcha_form": captcha_form,
    }
    return render(request, 'login.html', context)


def forgot_pd(request):
    captcha_form = CustomCaptchaForm()

    if request.method == 'POST':
        username = request.POST['username']

        try:
            user = User.objects.get(username=username)

            if user.status != 1:
                context = {
                    "captcha_form": captcha_form,
                    "msg": '只有普通用户能够修改密码'
                }
                return render(request, 'forgot_pd.html', context)

            captcha_form = CustomCaptchaForm(request.POST)

            if captcha_form.is_valid():
                if not User.objects.filter(username=username).exists():
                    # 用户名不存在，返回错误信息或重定向到适当的页面
                    error_message = "该用户名未注册"
                    context = {
                        "captcha_form": captcha_form,
                        "msg": error_message,
                    }
                    return render(request, 'forgot_pd.html', context)
                else:
                    # 修改密码
                    md5 = hashlib.md5()
                    n = random.randint(100000, 999999)
                    s = request.POST['pass'] + str(n)
                    md5.update(s.encode('utf-8'))

                    # 更新用户密码信息
                    user.password_hash = md5.hexdigest()
                    user.password_salt = n
                    user.update_at = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
                    user.save()

                    context = {
                        "captcha_form": captcha_form,
                        "msg": '密码修改成功'
                    }
                    return render(request, 'forgot_pd.html', context)
            else:
                context = {
                    "captcha_form": captcha_form,
                    "msg": '验证码错误'
                }
                return render(request, 'forgot_pd.html', context)

        except User.DoesNotExist:
            # 用户不存在，返回错误信息或重定向到适当的页面
            error_message = "该用户名未注册"
            context = {
                "captcha_form": captcha_form,
                "msg": error_message,
            }
            return render(request, 'forgot_pd.html', context)

        except Exception as e:
            print(e)
            context = {
                "captcha_form": captcha_form,
                "msg": '内部错误'
            }
            return render(request, 'forgot_pd.html', context)

    context = {
        "captcha_form": captcha_form,
    }
    return render(request, 'forgot_pd.html', context)


def index(request, *args, **kwargs):
    # 返回页面时，需要判断用户是否已经开始扫描，若开始扫描则应该持续显示该页面
    user_id = request.session['login_user'].get('id')
    user = User.objects.get(id=user_id)
    try:
        user_tuning_model = TuningModels.objects.filter(user=user).latest('end_time').tuning_model
        result_model_path = TuningModels.objects.filter(user=user).latest('end_time').result_model_path
    except TuningModels.DoesNotExist:
        user_tuning_model, result_model_path = None, None  # 或者设置为默认值，或者进行其他异常处理
    # print(user_tuning_model, result_model_path)
    context = {
        "user_tuning_model": user_tuning_model,
        "result_model_path": result_model_path
    }
    return render(request, 'index.html', context)


def predict_res(request):
    # pred_list, label_list = predict()  # 读取模型获取到的数据
    # html_content = "<h1>预测结果</h1><p>这里是预测的结果...</p>"  # 这里应该根据 predict 的结果动态生成
    # draw = draw_gauge(pred_list, label_list)
    #
    # return HttpResponse(draw.render_embed())
    pass


@require_http_methods(["POST"])
def dataset(request):
    if request.method == 'POST':
        # 从 request 中获取上传的文件和数据
        file = request.FILES.get('file') if request.FILES else None
        model = request.POST.get('model')

        # 检查是否收到了文件
        if not file:
            return JsonResponse({'status': 'error', 'message': 'No file provided'}, status=400)
        # 创建任务ID
        task_id = generate_task_id()
        request.session['task_id'] = task_id
        # 创建临时文件    
        temp_file = tempfile.NamedTemporaryFile(dir=os.path.join(STATICFILES_DIRS[0], 'tmp'), delete=False)
        try:
            # 将上传的文件保存到临时文件
            for chunk in file.chunks():
                temp_file.write(chunk)
            temp_file.close()  # 关闭文件，以便可以被其他操作打开
            # 将扫描数据存入数据库
            user_id = request.session['login_user'].get('id')
            user = User.objects.get(id=user_id)
            # 获取临时文件的路径
            temp_file_path = temp_file.name
            print("保存路径为", temp_file_path)
            record = Task.objects.create(
                task_id=task_id,
                user=user,
                temp_result_file_path=temp_file_path,
                start_time=timezone.localtime(timezone.now()),
                end_time=timezone.localtime(timezone.now()),
            )
            record.save()
            # 假设处理成功
            res = {
                'status': 'success',
                'message': 'File and model data processed',
                'model_used': model,
                'path': temp_file_path,
            }
            return JsonResponse(res, status=200)
        except Exception as e:
            os.unlink(temp_file_path)  # 删除临时文件
            return JsonResponse({'status': 'error', 'message': str(e)}, status=500)
    else:
        return JsonResponse({'status': 'error', 'message': 'Method Not Allowed'}, status=405)


def predict_exec(request):
    if request.method == 'POST':
        try:
            data = json.loads(request.body)
            model = data.get('model')
            path = data.get('path')
            attack_types = ["normal", "dos", "probe", "r2l", "u2r"]

            if not path:
                return JsonResponse({'status': 'error', 'message': 'Path is Not Found'}, status=404)

            if 'pkl' in model:
                model_path = model
                # 创建标签编码器实例并训练
                le_protocol_type = LabelEncoder()
                le_service = LabelEncoder()
                le_flag = LabelEncoder()

                # 加载训练集数据并拟合编码器
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

                df_train = pd.read_csv(os.path.join(STATICFILES_DIRS[0], 'data_set', 'KDDTrain\KDDTrain+.txt'),
                                       header=None, names=columns)

                # 拟合标签编码器
                le_protocol_type.fit(df_train['protocol_type'])
                le_service.fit(df_train['service'])
                le_flag.fit(df_train['flag'])

                if 'knn' in model_path.lower():
                    try:
                        latest_knn = TuningModels.objects.filter(
                            tuning_model='KNN Model'
                        ).latest('end_time')
                        if not latest_knn or not latest_knn.result_model_path:
                            return JsonResponse({
                                'status': 'error',
                                'message': '未找到KNN模型，请先进行模型训练'
                            }, status=404)
                        model_path = latest_knn.result_model_path
                        print(f"使用KNN模型预测：{model_path}")
                        predictions, y_test = predict_knn(
                            model_path, path, le_protocol_type, le_service, le_flag
                        )
                        accuracy = accuracy_score(y_test, predictions)
                        accuracy = '{:.2f}'.format(accuracy).rstrip('0').rstrip('.')
                        attack_count = Counter(predictions)
                    except TuningModels.DoesNotExist:
                        return JsonResponse({
                            'status': 'error',
                            'message': '未找到KNN模型，请先进行模型训练'
                        }, status=404)
                    except Exception as e:
                        print(f"预测过程中出错: {str(e)}")
                        return JsonResponse({
                            'status': 'error',
                            'message': str(e)
                        }, status=400)
                else:
                    # 使用随机森林预测
                    accuracy, precision, recall, f1, predictions, y_test = tuning_random_forest(
                        model_path, path, le_protocol_type, le_service, le_flag
                    )

                # 计算准确率和攻击类型统计
                accuracy = accuracy_score(y_test, predictions)
                accuracy = '{:.2f}'.format(accuracy).rstrip('0').rstrip('.')
                attack_count = Counter(predictions)
                attack_count_val = [(attack_type, attack_count[attack_type]) for attack_type in attack_types]

            else:
                # 使用基础模型的处理逻辑保持不变
                model_path = select_model(model)
                exec_start_time = time.time()
                pred_list, label_list = predict(model_path, path)
                exec_end_time = time.time()
                exec_time = format((exec_end_time - exec_start_time), '.0f')

                # 计算准确率并格式化，去掉多余的0
                accuracy = accuracy_score(label_list, pred_list)
                accuracy = '{:.2f}'.format(accuracy).rstrip('0').rstrip('.')
                attack_count = Counter(pred_list)
                attack_count_val = [(attack_type, attack_count[attack_type]) for attack_type in attack_types]

            # 更新任务状态
            task_id = request.session.get('task_id')
            if task_id:
                Task.objects.filter(task_id=task_id).update(
                    status='completed',
                    exec_time=exec_time if 'exec_time' in locals() else 0,
                    end_time=timezone.localtime(timezone.now()),
                )
            print(float(accuracy) * 100)
            res = {
                'status': 'success',
                'message': 'Completed the calculation of test set accuracy.',
                'overall_accuracy': float(accuracy) * 100,  # 转换为浮点数后再乘以100
                'attack_types': attack_types,
                'attack_count_val': attack_count_val
            }
            return JsonResponse(res, status=200)

        except Exception as e:
            print(f"预测过程中出错: {str(e)}")
            return JsonResponse({
                'status': 'error',
                'message': f'处理失败: {str(e)}'
            }, status=500)


def screen(request):
    # 展示图像
    def bar_echarts(base_data, tuning_data):
        from pyecharts.charts import Bar
        # 创建 Bar 实例
        bar = Bar(init_opts=opts.InitOpts(width="100%", height="400px"))

        accuracy_data = [base_data[0], format(tuning_data[0], '.2f')]  # 准确率数据
        precision_data = [base_data[1], format(tuning_data[1], '.2f')]  # 精确率数据
        recall_data = [base_data[2], format(tuning_data[2], '.2f')]  # 召回率数据
        # 添加X轴数据
        x_axis_data = ["随机森林算法(base)", tuning_data[3] + '(自定义调优)']
        bar.add_xaxis(x_axis_data)

        # 添加 Y 轴数据，这里可以添加多个系列，每个系列代表一个堆叠层
        bar.add_yaxis("准确率", accuracy_data)
        bar.add_yaxis("精确率", precision_data)
        bar.add_yaxis("召回率", recall_data)

        # 设置全局配置项，包括图注
        title_opts = opts.TitleOpts(title="模型性能指标堆叠柱状图")
        legend_opts = opts.LegendOpts(pos_top="8%")  # 设置图例位置在顶部
        bar.set_global_opts(title_opts, legend_opts)
        return bar.render_embed()

    def radar_echarts(tuning_data):
        """
        雷达图，显示两个模型之间的比较
        """
        model1 = [[75, 79.30, 49.43, 50.43]]
        model2 = [[format(tuning_data[0], '.2f'), format(tuning_data[1], '.2f'), format(tuning_data[2], '.2f'),
                   tuning_data[4]]]
        Radar_echarts = (
            Radar(init_opts=opts.InitOpts(width="100%", height="400px"))
            .add_schema(
                schema=[
                    opts.RadarIndicatorItem(name="准确率", max_=100),
                    opts.RadarIndicatorItem(name="精确率", max_=100),
                    opts.RadarIndicatorItem(name="召回率", max_=100),
                    opts.RadarIndicatorItem(name="F1总分", max_=100),
                    # opts.RadarIndicatorItem(name="预测时间", max_=0),
                ],
                splitarea_opt=opts.SplitAreaOpts(
                    is_show=True, areastyle_opts=opts.AreaStyleOpts(opacity=1)
                ),
                textstyle_opts=opts.TextStyleOpts(color="#000"),
            )
            .add(
                series_name="随机森林算法(base)",
                data=model1,
                linestyle_opts=opts.LineStyleOpts(color="#CD0000"),
            )

            .set_series_opts(label_opts=opts.LabelOpts(is_show=False))
            .set_global_opts(
                title_opts=opts.TitleOpts(title="模型综合雷达图"), legend_opts=opts.LegendOpts(pos_top="8%"),
            )
        )
        if model2[0][0] != '0.00':
            Radar_echarts.add(
                series_name=user_tuning_model + '(自定义调优)',
                data=model2,
                linestyle_opts=opts.LineStyleOpts(color="#5CACEE"),
            )
        return Radar_echarts.render_embed()

    def scatter_3d_echarts(scatter_3d_data):
        n_estimators = scatter_3d_data[0]
        max_depth = scatter_3d_data[1]
        accuracy = scatter_3d_data[2]
        execution_time = scatter_3d_data[3]
        data_accuracy = [[n, d, a] for n, d, a in zip(n_estimators, max_depth, accuracy)]
        data_time = [[n, d, e] for n, d, e in zip(n_estimators, max_depth, execution_time)]

        # 创建 3D 散点图
        scatter_3d = (
            Scatter3D(init_opts=opts.InitOpts(width="100%", height="600px"))
            .add(
                series_name="准确率",
                data=data_accuracy,
                xaxis3d_opts=opts.Axis3DOpts(name='n_estimators'),
                yaxis3d_opts=opts.Axis3DOpts(name='max_depth'),
                zaxis3d_opts=opts.Axis3DOpts(name='准确率'),
                itemstyle_opts=opts.ItemStyleOpts(color='blue'),
            )
            .add(
                series_name="预测时间",
                data=data_time,
                xaxis3d_opts=opts.Axis3DOpts(name='n_estimators'),
                yaxis3d_opts=opts.Axis3DOpts(name='max_depth'),
                zaxis3d_opts=opts.Axis3DOpts(name='预测时间'),
                itemstyle_opts=opts.ItemStyleOpts(color='red'),
            )
            .set_global_opts(
                title_opts=opts.TitleOpts(title="参数调优关系图(最近七天)"),
                legend_opts=opts.LegendOpts(is_show=True, pos_top="8%"),
            )
        )
        return scatter_3d.render_embed()

    # 获取数据
    base_forest_model_data = [75, 79.30, 49.43, 50.43]  # 系统自带的模型准确率、精确率、召回率和f1
    # 用户自训练的模型数据
    user_id = request.session['login_user'].get('id')
    user = User.objects.get(id=user_id)
    try:
        # 获取结果
        user_last_model = TuningModels.objects.filter(user=user).latest('end_time')
        user_tuning_model = user_last_model.tuning_model
        accuracy = user_last_model.accuracy
        precision = user_last_model.precision
        recall = user_last_model.recall
        f1 = user_last_model.f1_data
        n_estimators = user_last_model.n_estimators
        max_depth = user_last_model.max_depth
    except TuningModels.DoesNotExist:
        user_tuning_model, accuracy, precision, recall, f1 = '', 0, 0, 0, 0
        n_estimators, max_depth = 0, 0
    user_tuning_data = [accuracy, precision, recall, user_tuning_model, f1]

    now = timezone.now()

    # 计算七天前的时间
    seven_days_ago = now - timedelta(days=7)
    # 查询最近七天的数据
    recent_tuning_models = TuningModels.objects.filter(user=user, start_time__gte=seven_days_ago).order_by('start_time')
    n_estimators_list, max_depth_list, accuracy_list, exec_time_list = [], [], [], []
    for i in range(len(recent_tuning_models)):
        recent_tuning_n_estimators = recent_tuning_models[i].n_estimators
        recent_tuning_max_depth = recent_tuning_models[i].max_depth
        recent_tuning_accuracy = recent_tuning_models[i].accuracy
        recent_tuning_exec_time = recent_tuning_models[i].exec_time

        n_estimators_list.append(recent_tuning_n_estimators)
        max_depth_list.append(recent_tuning_max_depth)
        accuracy_list.append(recent_tuning_accuracy)
        exec_time_list.append(recent_tuning_exec_time)
    scatter_3d_data = [n_estimators_list, max_depth_list, accuracy_list, exec_time_list]
    print("最近七天的数据为:", scatter_3d_data)
    data = {
        'status': 'success',
        'bar_chart': bar_echarts(base_forest_model_data, user_tuning_data),
        'radar_chart': radar_echarts(user_tuning_data),
        'bar_3d': scatter_3d_echarts(scatter_3d_data)

    }
    return render(request, 'screen.html', data)


def model_info(request):
    data = {
        'status': 'success',
    }
    return render(request, 'model_info.html', data)


def dataset_result(request):
    # 定义列名
    columns = [
        'duration', 'protocol_type', 'service', 'flag', 'src_bytes',
        'dst_bytes', 'land', 'wrong_fragment', 'urgent', 'hot',
        'num_failed_logins', 'logged_in', 'num_compromised', 'root_shell',
        'su_attempted', 'num_root', 'num_file_creations', 'num_shells',
        'num_access_files', 'num_outbound_cmds', 'is_host_login',
        'is_guest_login', 'count', 'srv_count', 'serror_rate',
        'srv_serror_rate', 'rerror_rate', 'srv_rerror_rate', 'same_srv_rate',
        'diff_srv_rate', 'srv_diff_host_rate', 'dst_host_count',
        'dst_host_srv_count', 'dst_host_same_srv_rate', 'dst_host_diff_srv_rate',
        'dst_host_same_src_port_rate', 'dst_host_srv_diff_host_rate',
        'dst_host_serror_rate', 'dst_host_srv_serror_rate',
        'dst_host_rerror_rate', 'dst_host_srv_rerror_rate', 'attack', 'level'
    ]

    # 读取NSL-KDD测试集数据
    df = pd.read_csv(os.path.join(STATICFILES_DIRS[0], 'data_set', 'KDDTest', 'KDDTest+.txt'),
                     header=None, names=columns)

    # 将攻击类型映射为主要类别
    attack_mapping = {
        'normal': 'normal',
        'back': 'dos', 'land': 'dos', 'neptune': 'dos', 'pod': 'dos',
        'smurf': 'dos', 'teardrop': 'dos',
        'ipsweep': 'probe', 'nmap': 'probe', 'portsweep': 'probe', 'satan': 'probe',
        'ftp_write': 'r2l', 'guess_passwd': 'r2l', 'imap': 'r2l', 'multihop': 'r2l',
        'phf': 'r2l', 'spy': 'r2l', 'warezclient': 'r2l', 'warezmaster': 'r2l',
        'buffer_overflow': 'u2r', 'loadmodule': 'u2r', 'perl': 'u2r', 'rootkit': 'u2r'
    }
    df['attack_category'] = df['attack'].map(lambda x: attack_mapping.get(x, 'unknown'))
    print(f"攻击类型分布为：{df['attack_category']}")

    # 1. 攻击类型分布饼图
    attack_dist = (
        Pie(init_opts=opts.InitOpts(width="100%", height="400px"))
        .add(
            "",
            [list(z) for z in df['attack_category'].value_counts().items()],
            radius=["40%", "75%"],
        )
        .set_global_opts(
            title_opts=opts.TitleOpts(title="攻击类型分布"),
            legend_opts=opts.LegendOpts(orient="vertical", pos_top="15%", pos_left="2%")
        )
    )

    # 2. 协议类型统计柱状图
    protocol_stats = (
        Bar(init_opts=opts.InitOpts(width="100%", height="400px"))
        .add_xaxis(df['protocol_type'].unique().tolist())
        .add_yaxis("数量", df['protocol_type'].value_counts().tolist())
        .set_global_opts(
            title_opts=opts.TitleOpts(title="协议类型统计"),
            xaxis_opts=opts.AxisOpts(axislabel_opts=opts.LabelOpts(rotate=45)),
            toolbox_opts=opts.ToolboxOpts()
        )
    )

    # 3. 服务类型TOP10统计
    service_top10 = (
        Bar(init_opts=opts.InitOpts(width="100%", height="400px"))
        .add_xaxis(df['service'].value_counts().head(10).index.tolist())
        .add_yaxis("数量", df['service'].value_counts().head(10).values.tolist())
        .set_global_opts(
            title_opts=opts.TitleOpts(title="服务类型TOP10统计"),
            xaxis_opts=opts.AxisOpts(axislabel_opts=opts.LabelOpts(rotate=45)),
            toolbox_opts=opts.ToolboxOpts()
        )
    )

    # 4. 连接时长分布折线图
    duration_stats = (
        Line(init_opts=opts.InitOpts(width="100%", height="400px"))
        .add_xaxis(
            [str(x) for x in range(10)]
        )
        .add_yaxis(
            "连接数量",
            df['duration'].value_counts().sort_index().head(10).values.tolist(),
            is_smooth=True
        )
        .set_global_opts(
            title_opts=opts.TitleOpts(title="连接时长分布(前10个时间点)"),
            toolbox_opts=opts.ToolboxOpts()
        )
    )

    data = {
        'status': 'success',
        'attack_dist': attack_dist.dump_options(),
        'protocol_stats': protocol_stats.dump_options(),
        'service_top10': service_top10.dump_options(),
        'duration_stats': duration_stats.dump_options(),
    }

    return render(request, 'dataset_result.html', data)


def model_tuning(request):
    data = {
        'status': 'success',
    }
    return render(request, 'model_tuning.html', data)


def model_tuning_random_forest(request):
    user_id = request.session['login_user'].get('id')
    user = User.objects.get(id=user_id)
    if request.method == 'POST':
        n_estimators = int(request.POST.get('n_estimators'))
        criterion = request.POST.get('criterion')
        max_depth = int(request.POST.get('max_depth'))
        max_features = request.POST.get('max_features')
        random_state = int(request.POST.get('random_state'))
        # 将训练数据存入数据库
        tuning_id = generate_task_id()
        request.session['tuning_id'] = tuning_id
        tuning_model = 'Random Forest'
        tuning_models = TuningModels.objects.create(
            tuning_id=tuning_id,
            user=user,
            tuning_model=tuning_model,
            n_estimators=n_estimators,
            criterion=criterion,
            max_depth=max_depth,
            max_features=max_features,
            random_state=random_state,

            start_time=timezone.localtime(timezone.now()),
            end_time=timezone.localtime(timezone.now()),
        )
        tuning_models.save()
        # 这里可以添加你的模型调优逻辑
        """
        main_model_tuning(
        n_estimators: int,
        criterion: str,
        max_depth: int,
        max_features: str,
        random_state: int)
        """
        exec_start_time = time.time()
        accuracy, precision, recall, f1, model_file_path = main_model_tuning(n_estimators, criterion, max_depth,
                                                                             max_features, random_state)
        exec_end_time = time.time()
        exec_time = format((exec_end_time - exec_start_time), '.0f')
        # print(accuracy, precision, recall, f1, model_file_path)
        accuracy = float(format(accuracy[0], '.4f')) * 100  # 处理小数
        precision = float(format(precision[0], '.4f')) * 100
        recall = float(format(recall[0], '.4f')) * 100
        f1 = float(format(f1, '.4f')) * 100

        if accuracy is None:
            return JsonResponse({'status': 'error', 'message': 'Model tuned Failed'})
        # 需要将调试的参数值以及结果存储置数据库
        tuning_id = request.session['tuning_id']
        if tuning_id is not None:
            TuningModels.objects.filter(tuning_id=tuning_id).update(
                accuracy=accuracy,
                precision=precision,
                recall=recall,
                f1_data=f1,
                exec_time=exec_time,
                result_model_path=model_file_path,
                end_time=timezone.localtime(timezone.now()),
            )

        response_data = {
            'status': 'success',
            'message': 'Model tuned successfully',
            'accuracy': accuracy,
            'precision': precision,
            'recall': recall,
            'f1': f1,
            'model_file_path': model_file_path
        }

        # 返回JSON响应
        return JsonResponse(response_data)

    else:
        # 需要将最近一次的数据返回
        try:
            latest_tuning_model = TuningModels.objects.filter(user=user, tuning_model='Random Forest').latest(
                'end_time')
        except TuningModels.DoesNotExist:
            return render(request, 'random_forest_tuning.html', context={'n_estimators': None})
        context = {
            'n_estimators': latest_tuning_model.n_estimators,
            'criterion': latest_tuning_model.criterion,
            'max_depth': latest_tuning_model.max_depth,
            'max_features': latest_tuning_model.max_features,
            'random_state': latest_tuning_model.random_state,

            # 将上次得到的数据也返回
            'accuracy': latest_tuning_model.accuracy,
            'precision': latest_tuning_model.precision,
            'recall': latest_tuning_model.recall
        }
        return render(request, 'random_forest_tuning.html', context)


def reset_parameter_random_forest(request):
    return render(request, 'random_forest_tuning.html', context={'n_estimators': None})


def model_tuning_knn(request):
    user_id = request.session['login_user'].get('id')
    user = User.objects.get(id=user_id)

    if request.method == 'POST':
        try:
            # 获取参数
            n_neighbors = int(request.POST.get('n_neighbors', 5))
            p_measure = int(request.POST.get('p_measure', 2))
            weights = request.POST.get('weights', 'uniform')

            # 生成并存储tuning_id
            tuning_id = generate_task_id()
            request.session['tuning_id'] = tuning_id

            # 获取上一次的训练结果（如果有）
            try:
                previous_model = TuningModels.objects.filter(
                    user=user,
                    tuning_model='KNN Model'
                ).latest('end_time')
                previous_metrics = {
                    'accuracy': previous_model.accuracy,
                    'precision': previous_model.precision,
                    'recall': previous_model.recall
                }
            except TuningModels.DoesNotExist:
                previous_metrics = None

            # 创建新的调优记录
            tuning_models = TuningModels.objects.create(
                tuning_id=tuning_id,
                user=user,
                tuning_model='KNN Model',
                n_neighbors=n_neighbors,
                p_measure=p_measure,
                weights=weights,
                start_time=timezone.now()
            )

            # 训练模型并获取结果
            data = get_processed_data()
            result = main_model_tuning_knn(
                n_neighbors=n_neighbors,
                p_measure=p_measure,
                weights=weights,
                X_train=data['X_train'],
                y_train=data['y_train'],
                X_test=data['X_test'],
                y_test=data['y_test']
            )

            # 更新调优记录
            metrics = result['metrics']
            tuning_models.accuracy = round(metrics['accuracy'] * 100, 2)
            tuning_models.precision = round(metrics['precision'] * 100, 2)
            tuning_models.recall = round(metrics['recall'] * 100, 2)
            tuning_models.exec_time = round(metrics['exec_time'], 2)
            tuning_models.result_model_path = result['model_path']
            tuning_models.end_time = timezone.now()
            tuning_models.save()

            # 准备响应数据
            response_data = {
                'status': 'success',
                'message': 'Model tuned successfully',
                'accuracy': tuning_models.accuracy,
                'precision': tuning_models.precision,
                'recall': tuning_models.recall,
                'previous_metrics': previous_metrics
            }

            return JsonResponse(response_data)

        except Exception as e:
            print(f"模型训练过程中出错: {e}")
            return JsonResponse({
                'status': 'error',
                'message': str(e)
            })

    else:
        # GET请求处理保持不变
        try:
            latest_tuning_model = TuningModels.objects.filter(
                user=user,
                tuning_model='KNN Model'
            ).latest('end_time')

            context = {
                'n_neighbors': latest_tuning_model.n_neighbors,
                'p_measure': latest_tuning_model.p_measure,
                'weights': latest_tuning_model.weights,
                'accuracy': latest_tuning_model.accuracy,
                'precision': latest_tuning_model.precision,
                'recall': latest_tuning_model.recall
            }
        except TuningModels.DoesNotExist:
            context = {'n_neighbors': None}

        return render(request, 'knn_tuning.html', context)


def reset_parameter_knn_model(request):
    return render(request, 'knn_tuning.html', context={'n_neighbors': None})


def upload_pcapng(request):
    from decimal import Decimal
    from datetime import datetime
    import json
    start_time = time.time()

    def res_unique_rm_city(data, is_attack_data=False):
        """
        处理数据去重
        :param data: 要处理的数据列表
        :param is_attack_data: 是否是攻击类型数据（结构更简单）
        """
        unique_values = set()
        unique_data = []

        if is_attack_data:
            # 处理攻击类型数据 [source_ip, attack_type]
            for item in data:
                if item[1] not in unique_values:
                    unique_values.add(item[1])
                    unique_data.append(item)

            counter = Counter([item[1] for item in data])
            for item in unique_data:
                item.append(counter[item[1]])  # 添加计数
            return unique_data
        else:
            # 处理详细数据包信息 [source_ip, dest_ip, url, attack_type, packet_info]
            for item in data:
                unique_key = tuple(item[:4])
                if unique_key not in unique_values:
                    unique_values.add(unique_key)
                    unique_data.append(item)

            counter = Counter(tuple(item[:4]) for item in data)

            for item in unique_data:
                unique_key = tuple(item[:4])
                count = counter[unique_key]
                packet_info = item[4] if len(item) > 4 else {}

                new_item = [
                    item[0],  # source_ip
                    item[1],  # destination_ip
                    item[2],  # url
                    item[3],  # attack_type
                    count,  # 计数
                    packet_info  # 详细信息字典
                ]
                item[:] = new_item

            return unique_data

    if request.method == 'POST' and request.FILES['file']:
        file = request.FILES['file']
        file_name = 'file.pcap'  # 指定文件名
        # 为了保证始终只有一个文件，则将目录中的文件先删除在保存
        file_path = os.path.join(default_storage.location, file_name)
        if default_storage.exists(file_path):
            default_storage.delete(file_path)

        # 保存新的文件
        file_path = default_storage.save(file_name, file)
        file_path = os.path.join(default_storage.location, file_path)
        packets = rdpcap(file_path)  # 读取所有数据包

        # 统计所有数据包信息
        packet_stats = {
            'total_packets': len(packets),
            'protocols': defaultdict(int),
            'http_packets': 0,
            'tcp_packets': 0,
            'udp_packets': 0,
            'other_packets': 0,
            'total_bytes': 0,
            'avg_packet_size': 0
        }

        # 分析每个数据包
        for packet in packets:
            packet_stats['total_bytes'] += len(packet)

            if packet.haslayer(TCP):
                packet_stats['tcp_packets'] += 1
                if packet.haslayer(HTTPRequest):
                    packet_stats['http_packets'] += 1
            elif packet.haslayer(UDP):
                packet_stats['udp_packets'] += 1
            else:
                packet_stats['other_packets'] += 1

            # 获取协议名称
            if packet.haslayer(IP):
                proto_name = packet[IP].get_field('proto').i2s.get(packet[IP].proto, str(packet[IP].proto))
                packet_stats['protocols'][proto_name] += 1

        # 计算平均包大小
        packet_stats['avg_packet_size'] = round(packet_stats['total_bytes'] / packet_stats['total_packets'], 2)

        # 将协议统计转换为图表数据
        protocol_data = [{"name": proto, "value": count}
                         for proto, count in packet_stats['protocols'].items()]
        protocol_names = json.dumps([item['name'] for item in protocol_data])
        protocol_values = json.dumps([item['value'] for item in protocol_data])

        data = []
        attack_unique_data = []
        total_packets = len(packets)  # 总数据包数
        attack_packets = 0  # 攻击数据包数

        for packet in packets:
            ip_layer = packet.getlayer(IP)
            tcp_layer = packet.getlayer(TCP)
            http_layer = packet.getlayer(HTTPRequest)

            if ip_layer is not None:
                # 转换时间戳
                try:
                    timestamp = float(packet.time)
                    formatted_time = datetime.fromtimestamp(timestamp).strftime('%Y-%m-%d %H:%M:%S.%f')
                except (TypeError, ValueError):
                    formatted_time = "Unknown Time"

                # 初始化基本信息
                packet_info = {
                    'source_ip': ip_layer.src,
                    'destination_ip': ip_layer.dst,
                    'timestamp': formatted_time,
                    'length': len(packet),
                    'source_mac': packet.src,
                    'dest_mac': packet.dst,
                    'protocol': packet.proto,
                    'packet_id': packet.id,
                }

                # 添加 TCP 相关信息（如果存在）
                if tcp_layer is not None:
                    packet_info.update({
                        'source_port': tcp_layer.sport,
                        'destination_port': tcp_layer.dport,
                    })
                else:
                    packet_info.update({
                        'source_port': 'N/A',
                        'destination_port': 'N/A',
                    })

                # 添加 HTTP 相关信息（如果存在）
                if http_layer is not None:
                    packet_info.update({
                        'method': http_layer.Method.decode(),
                        'url': http_layer.Host.decode() + http_layer.Path.decode(),
                        'user_agent': http_layer.fields.get('User-Agent', b'').decode('utf-8', 'ignore'),
                        'referer': http_layer.fields.get('Referer', b'').decode('utf-8', 'ignore'),
                    })
                else:
                    packet_info.update({
                        'method': 'N/A',
                        'url': 'N/A',
                        'user_agent': 'N/A',
                        'referer': 'N/A',
                    })

                # 匹配url是否为恶意流量（仅对HTTP包进行检查）
                if http_layer is not None:
                    is_attack = http_attack(packet_info['url'])
                    if is_attack[1] is not None:
                        attack_packets += 1
                        attack_unique_data.append([packet_info['source_ip'], is_attack[0][0]])
                        packet_info['attack'] = is_attack[0][0]
                        data.append([
                            packet_info['source_ip'],
                            packet_info['destination_ip'],
                            packet_info['url'],
                            packet_info['attack'],
                            packet_info
                        ])
            else:
                continue

        table_val = res_unique_rm_city(data)  # 处理详细数据

        # 计算正常流量数
        normal_packets = total_packets - attack_packets

        # 处理攻击类型数据
        if len(attack_unique_data) != 0:
            datas = res_unique_rm_city(attack_unique_data, is_attack_data=True)
            attack_type = []
            for vul in datas:
                i = {"value": vul[2], "name": vul[1]}
                attack_type.append(i)
            # 将数据转换为JSON字符串
            attack_names = json.dumps([item['name'] for item in attack_type])
            attack_values = json.dumps([item['value'] for item in attack_type])
        else:
            attack_names = '[]'
            attack_values = '[]'
            attack_type = []

        # 计算总流量数据
        total_data = {
            'total_packets': total_packets,
            'attack_packets': attack_packets,
            'normal_packets': normal_packets,
            'http_packets': packet_stats['http_packets'],
            'tcp_packets': packet_stats['tcp_packets'],
            'udp_packets': packet_stats['udp_packets'],
            'other_packets': packet_stats['other_packets'],
            'total_bytes': packet_stats['total_bytes'],
            'avg_packet_size': packet_stats['avg_packet_size']
        }

        # 计算威胁检出率
        threat_rate = round((attack_packets / total_packets * 100), 2) if total_packets > 0 else 0

        end_time = time.time()
        run_time = round((end_time - start_time) / 60, 2)
        is_upload = 'is_upload'
        return render(request, 'upload_pcapng.html',
                      {'data': table_val,
                       'attack_names': attack_names,
                       'attack_values': attack_values,
                       'protocol_names': protocol_names,
                       'protocol_values': protocol_values,
                       'attack_data': {'attack_type': attack_type},
                       'total_data': total_data,
                       'is_upload': is_upload,
                       'run_time': run_time,
                       'threat_rate': threat_rate})
    is_upload = 'is_upload'
    return render(request, 'upload_pcapng.html', {'is_upload': is_upload})


def ip_rule_list(request):
    """显示IP规则列表"""
    whitelist = IPAddressRule.objects.filter(rule_type='white')
    blacklist = IPAddressRule.objects.filter(rule_type='black')

    context = {
        'whitelist': whitelist,
        'blacklist': blacklist
    }
    return render(request, 'myadmin/ip_rules.html', context)


def add_ip_rule(request):
    """添加IP规则"""
    if request.method == 'POST':
        ip_address = request.POST.get('ip_address')
        rule_type = request.POST.get('rule_type')
        description = request.POST.get('description', '')

        try:
            # 检查IP是否已存在
            if IPAddressRule.objects.filter(ip_address=ip_address).exists():
                messages.error(request, f'IP地址 {ip_address} 已存在于规则列表中')
                return redirect('ip_rule_list')

            # 添加防火墙规则
            if FirewallManager.add_rule(ip_address, rule_type):
                # 保存到数据库
                IPAddressRule.objects.create(
                    ip_address=ip_address,
                    rule_type=rule_type,
                    description=description
                )
                messages.success(request, f'成功添加{rule_type}规则：{ip_address}')
            else:
                messages.error(request, f'添加防火墙规则失败：{ip_address}')

        except ValueError as e:
            messages.error(request, str(e))
        except Exception as e:
            messages.error(request, f'添加规则时发生错误：{str(e)}')

    return redirect('ip_rule_list')


def delete_ip_rule(request, rule_id):
    """删除IP规则"""
    try:
        rule = IPAddressRule.objects.get(id=rule_id)

        # 删除防火墙规则
        if FirewallManager.remove_rule(rule.ip_address, rule.rule_type):
            # 从数据库中删除
            rule.delete()
            messages.success(request, f'成功删除规则：{rule.ip_address}')
        else:
            messages.error(request, f'删除防火墙规则失败：{rule.ip_address}')

    except IPAddressRule.DoesNotExist:
        messages.error(request, '规则不存在')
    except Exception as e:
        messages.error(request, f'删除规则时发生错误：{str(e)}')

    return redirect('ip_rule_list')
