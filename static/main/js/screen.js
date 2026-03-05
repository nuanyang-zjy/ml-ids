const myChart = echarts.init(document.getElementById('chart-container'));
// 配置图表
const option = {
    // ... 根据返回的数据配置图表 ...
    series: [{
        name: 'Accuracy',
        type: 'gauge',
        detail: {formatter: '{value}%'},
        data: [{value: '{{ overall_accuracy }}'}],
    }]
};
myChart.setOption(option);
