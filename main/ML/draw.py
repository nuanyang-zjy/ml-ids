from collections import Counter

from pyecharts.charts import Pie, Bar, Gauge
from pyecharts import options as opts
from sklearn.metrics import precision_score, recall_score, f1_score, accuracy_score


def draw_pie(pred_list=None, label_list=None):
    attack_types = ["normal", "dos", "probe", "r2l", "u2r"]

    # 统计每种攻击类型的数量
    attack_count = Counter(pred_list)

    # 创建饼状图的数据
    data = [(attack_type, attack_count[attack_type]) for attack_type in attack_types]

    # 创建饼状图
    pie = Pie()
    pie.add(
        "",
        data,
        radius=["40%", "70%"]  # 设置内外半径，形成环形图
    )

    # 设置全局选项
    pie.set_global_opts(
        title_opts=opts.TitleOpts(
            title="Attack Types Distribution",
            pos_left="center",
            pos_top="5%",
            title_textstyle_opts=opts.TextStyleOpts(font_size=20)
        ),
        legend_opts=opts.LegendOpts(
            orient="vertical",
            pos_left="left",
            pos_top="middle",
            textstyle_opts=opts.TextStyleOpts(font_size=12)
        )
    )

    return pie


def draw_gauge(label_list=None, pred_list=None):
    # 计算总体准确率
    overall_accuracy = accuracy_score(label_list, pred_list)
    # 创建仪表盘
    gauge = Gauge()
    gauge.add(
        "Accuracy",
        [("Overall Accuracy", overall_accuracy * 100)],  # * 100 to convert to percentage
        detail_label_opts=opts.GaugeDetailOpts(formatter="{value}%")
    )

    # 设置全局选项
    gauge.set_global_opts(
        title_opts=opts.TitleOpts(
            title="Model Overall Accuracy",
            pos_left="center",
            pos_top="5%",
            title_textstyle_opts=opts.TextStyleOpts(font_size=20)
        )
    )
    # 设置仪表盘的轴和分区颜色
    gauge.set_series_opts(
        axisline_opts=opts.AxisLineOpts(
            linestyle_opts=opts.LineStyleOpts(
                color=[
                    (0.6, "#67e0e3"),  # 蓝色表示0-60%
                    (0.8, "#37a2da"),  # 青色表示60-80%
                    (1.0, "#fd666d")  # 红色表示80-100%
                ],
                width=30  # 设置轴线宽度
            )
        ),
        title_label_opts=opts.LabelOpts(
            font_size=16,
            color="#000",
            font_family="Arial",
            font_weight="bold"
        )
    )
    return gauge


def draw_3(self, opts=None):
    return None


def draw_4(self, opts=None):
    return None


def draw_5(self, opts=None):
    return None
