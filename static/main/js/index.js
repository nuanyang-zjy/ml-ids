function getCookie(name) {
  let cookieValue = null;
  if (document.cookie && document.cookie !== '') {
    const cookies = document.cookie.split(';');
    for (let i = 0; i < cookies.length; i++) {
      const cookie = cookies[i].trim();
      if (cookie.substring(0, name.length + 1) === (name + '=')) {
        cookieValue = decodeURIComponent(cookie.substring(name.length + 1));
        break;
      }
    }
  }
  return cookieValue;
}
const fileInput = document.getElementById('file-input');
const fileLabel = document.getElementById('file-input-label');
// console.log("文件：", fileLabel);
// 监听文件输入框的 "change" 事件
fileInput.addEventListener('change', function() {
// 获取选择的文件名
const fileName = this.files[0] ? this.files[0].name : '';

// 更新标签的内容
fileLabel.textContent = fileName;
});
let isRequestPending = false; // 标志变量
function importData() {
    if (isRequestPending) {
        console.log('请求已发送，正在处理中...');
        return;
    }
    event.preventDefault();
    const fileInput = document.getElementById('file-input');
    const file = fileInput.files[0];
    const modelSelect = document.getElementById('model-select');
    const model = modelSelect.value;
    var scan_button = document.getElementById('scan-button-id');
    var Loading = document.getElementById('loading');

    if (file && file.type === 'text/plain') {
        const csrftoken = getCookie('csrftoken');
        isRequestPending = true;
        const formData = new FormData();
        formData.append('file', file);
        formData.append('model', model);

        fetch('dataset', {
            method: 'POST',
            headers: {
                'X-CSRFToken': csrftoken
            },
            body: formData
        })
        .then(response => response.json())
        .then(data => {
            if (data.status === 'success') {
                $('#chartModal').modal('show');
                console.log("文件上传成功");

                // 按钮置灰
                scan_button.style.backgroundColor = '#ccc';
                scan_button.disabled = true;
                scan_button.textContent = '优化模型中...';
                Loading.style.display = 'block';
                execScan(data.model_used, data.path);
                isRequestPending = false;
            } else {
                isRequestPending = false;
                const errorMessage = data.message || '上传失败';
                showToast(errorMessage, 'error');
            }
        })
        .catch(error => {
            isRequestPending = false;
            console.error('Error importing data:', error);
            showToast('数据导入失败，请重试', 'error');
        });
    } else {
        showToast("请选择 TXT 格式的文件进行导入", 'warning');
    }
}

function execScan(model, path) {
    var csrftoken = getCookie('csrftoken');
    var result_echarts = document.getElementById('result-echarts');
    var scan_button = document.getElementById('scan-button-id');
    var Loading = document.getElementById('loading');

    fetch('predict_exec', {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json',
            'X-CSRFToken': csrftoken
        },
        body: JSON.stringify({model: model, path: path})
    })
    .then(response => {
        // 确保即使是错误响应也被正确处理
        return response.json().then(data => {
            if (!response.ok) {
                throw new Error(data.message || '网络错误');
            }
            return data;
        });
    })
    .then(data => {
        if (data.status === 'success') {
            // 将数据结果展示
            result_echarts.style.display = 'block';
            scan_button.style.backgroundColor = '';
            scan_button.disabled = false;
            scan_button.textContent = '开始检测';
            Loading.style.display = 'none';
            
            // 更新图表
            updateCharts(data);
            showToast('检测完成', 'success');
        } else {
            throw new Error(data.message || '处理失败');
        }
    })
    .catch(error => {
        console.error('扫描出错:', error);
        result_echarts.style.display = 'none';  // 隐藏图表区域
        scan_button.style.backgroundColor = '';
        scan_button.disabled = false;
        scan_button.textContent = '开始检测';
        Loading.style.display = 'none';
        
        // 显示更友好的错误信息
        let errorMessage = error.message;
        if (errorMessage.includes('特征转换失败')) {
            errorMessage = '数据格式不兼容，请检查输入数据是否符合要求';
        }
        showToast(errorMessage, 'error');
    });
}

// 添加提示框函数
function showToast(message, type = 'info') {
    const toastContainer = document.getElementById('toast-container');
    if (!toastContainer) {
        const container = document.createElement('div');
        container.id = 'toast-container';
        container.style.cssText = `
            position: fixed;
            top: 20px;
            right: 20px;
            z-index: 1050;
        `;
        document.body.appendChild(container);
    }

    const toast = document.createElement('div');
    toast.className = `toast ${type}`;
    toast.style.cssText = `
        min-width: 200px;
        margin-bottom: 10px;
        padding: 15px;
        border-radius: 4px;
        font-size: 14px;
        opacity: 0;
        transition: opacity 0.3s ease-in-out;
    `;

    // 根据类型设置不同的样式
    switch(type) {
        case 'success':
            toast.style.backgroundColor = '#d4edda';
            toast.style.color = '#155724';
            toast.style.border = '1px solid #c3e6cb';
            break;
        case 'error':
            toast.style.backgroundColor = '#f8d7da';
            toast.style.color = '#721c24';
            toast.style.border = '1px solid #f5c6cb';
            break;
        case 'warning':
            toast.style.backgroundColor = '#fff3cd';
            toast.style.color = '#856404';
            toast.style.border = '1px solid #ffeeba';
            break;
        default:
            toast.style.backgroundColor = '#d1ecf1';
            toast.style.color = '#0c5460';
            toast.style.border = '1px solid #bee5eb';
    }

    toast.textContent = message;
    document.getElementById('toast-container').appendChild(toast);

    // 显示提示框
    setTimeout(() => {
        toast.style.opacity = '1';
    }, 10);

    // 错误消息显示时间延长到5秒
    const displayTime = type === 'error' ? 5000 : 3000;
    
    setTimeout(() => {
        toast.style.opacity = '0';
        setTimeout(() => {
            toast.remove();
        }, 300);
    }, displayTime);
}

// 更新图表函数
function updateCharts(data) {
    const myChart0 = echarts.init(document.getElementById('chart-container0'), null, {
        height: '400px'
    });
    const myChart1 = echarts.init(document.getElementById('chart-container1'), null, {
        height: '400px'
    });

    // 准确率仪表盘
    const option0 = {
        title: {
            text: '准确率',
            left: 'center',
            top: '2%',
            textStyle: {
                fontSize: 20
            }
        },
        grid: {
            top: '15%',
            bottom: '15%',
            left: '15%',
            right: '15%'
        },
        series: [{
            name: 'Accuracy',
            type: 'gauge',
            detail: {
                formatter: function(value) {
                    // 将数值保留最多2位小数
                    return value.toFixed(2).replace(/\.?0+$/, '') + '%';
                },
                fontSize: 20
            },
            data: [{value: data.overall_accuracy}],
            axisLabel: {
                formatter: function(value) {
                    return value.toFixed(1) + '%';
                }
            }
        }]
    };

    // 攻击类型饼图
    const option1 = {
        title: {
            text: '攻击类型',
            left: 'center',
            top: '2%',
            textStyle: {
                fontSize: 20
            }
        },
        tooltip: {},
        legend: {
            orient: 'vertical',
            left: 'left',
            data: data.attack_types
        },
        grid: {
            top: '15%',
            bottom: '15%',
            left: '15%',
            right: '15%'
        },
        series: [{
            name: 'Attack Types',
            type: 'pie',
            radius: ['40%', '70%'],
            data: data.attack_count_val.map(item => ({
                name: item[0],
                value: item[1]
            }))
        }]
    };

    myChart0.setOption(option0);
    myChart1.setOption(option1);
}