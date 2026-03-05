document.addEventListener('DOMContentLoaded', function() {
    const trainButton = document.getElementById('submitButton');
    const loadingSpinner = document.getElementById('loadingSpinner');
    const form = document.getElementById('tuningForm');
    
    trainButton.addEventListener('click', function() {
        // 按钮置灰
        this.style.backgroundColor = '#ccc';
        this.disabled = true;
        this.textContent = '优化模型中...';
        loadingSpinner.style.display = 'block';
        
        // 获取表单数据
        const formData = new FormData(form);
        
        // 发送请求
        fetch(form.action, {
            method: 'POST',
            body: formData,
            headers: {
                'X-CSRFToken': formData.get('csrfmiddlewaretoken')
            }
        })
        .then(response => response.json())
        .then(data => {
            if (data.status === 'success') {
                // 恢复按钮状态
                trainButton.style.backgroundColor = '';
                trainButton.disabled = false;
                trainButton.innerHTML = '<i class="fas fa-play-circle me-2"></i>确认并开始训练';
                loadingSpinner.style.display = 'none';
                
                // 更新性能指标并显示趋势
                updateMetricsWithTrend(data);
                showMessage('模型训练成功！', 'success');
            } else {
                showMessage(data.message || '训练过程中出现错误', 'error');
            }
        })
        .catch(error => {
            console.error('Error:', error);
            showMessage('请求失败，请重试', 'error');
        })
        .finally(() => {
            if (trainButton.disabled) {
                trainButton.style.backgroundColor = '';
                trainButton.disabled = false;
                trainButton.innerHTML = '<i class="fas fa-play-circle me-2"></i>确认并开始训练';
                loadingSpinner.style.display = 'none';
            }
        });
    });
});

function updateMetricsWithTrend(data) {
    // 更新准确率并显示趋势
    const accuracyBar = document.getElementById('accuracy');
    const accuracyUp = document.getElementById('i-accuracy-up');
    const accuracyDown = document.getElementById('i-accuracy-down');
    
    const currentAccuracy = parseFloat(accuracyBar.textContent);
    accuracyBar.style.width = data.accuracy + '%';
    accuracyBar.textContent = data.accuracy + '%';
    
    if (data.accuracy > currentAccuracy) {
        accuracyUp.style.display = 'inline';
        accuracyDown.style.display = 'none';
    } else if (data.accuracy < currentAccuracy) {
        accuracyUp.style.display = 'none';
        accuracyDown.style.display = 'inline';
    }
    
    // 更新精确率并显示趋势
    const precisionBar = document.getElementById('precision');
    const precisionUp = document.getElementById('i-precision-up');
    const precisionDown = document.getElementById('i-precision-down');
    
    const currentPrecision = parseFloat(precisionBar.textContent);
    precisionBar.style.width = data.precision + '%';
    precisionBar.textContent = data.precision + '%';
    
    if (data.precision > currentPrecision) {
        precisionUp.style.display = 'inline';
        precisionDown.style.display = 'none';
    } else if (data.precision < currentPrecision) {
        precisionUp.style.display = 'none';
        precisionDown.style.display = 'inline';
    }
    
    // 更新召回率并显示趋势
    const recallBar = document.getElementById('recall');
    const recallUp = document.getElementById('i-recall-up');
    const recallDown = document.getElementById('i-recall-down');
    
    const currentRecall = parseFloat(recallBar.textContent);
    recallBar.style.width = data.recall + '%';
    recallBar.textContent = data.recall + '%';
    
    if (data.recall > currentRecall) {
        recallUp.style.display = 'inline';
        recallDown.style.display = 'none';
    } else if (data.recall < currentRecall) {
        recallUp.style.display = 'none';
        recallDown.style.display = 'inline';
    }
}

function showMessage(message, type) {
    // 创建消息元素
    const messageDiv = document.createElement('div');
    messageDiv.className = `alert alert-${type === 'success' ? 'success' : 'danger'} alert-dismissible fade show`;
    messageDiv.role = 'alert';
    messageDiv.innerHTML = `
        ${message}
        <button type="button" class="btn-close" data-bs-dismiss="alert" aria-label="Close"></button>
    `;
    
    // 添加到页面
    const container = document.querySelector('.container');
    container.insertBefore(messageDiv, container.firstChild);
    
    // 5秒后自动消失
    setTimeout(() => {
        messageDiv.remove();
    }, 5000);
}

// 更新滑动条值的显示
function updateValue(value, elementId) {
    document.getElementById(elementId).textContent = value;
}