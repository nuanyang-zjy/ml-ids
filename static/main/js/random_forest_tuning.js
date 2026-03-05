function updateValue(val, spanId) {
  document.getElementById(spanId).innerHTML = val;
}

document.getElementById('submitButton').addEventListener('click', function() {
    var Loading = document.getElementById('loading');
    // 按钮置灰
    this.style.backgroundColor = '#ccc'; // 修改按钮背景颜色为灰色
    this.disabled = true; // 禁用按钮，使其不可点击
    this.textContent = '优化模型中...'; // 更改按钮文字
    Loading.style.display = 'block';
    submitForm();
});

function submitForm() {
    var formData = new FormData(document.getElementById('tuningForm'));
    // 获取CSRF令牌
    var csrftoken = document.querySelector('[name=csrfmiddlewaretoken]').value;
    var submitButton = document.getElementById('submitButton');
    var Loading = document.getElementById('loading');

    var tuning_result = document.getElementById('tuning-result');
    var result_accuracy = document.getElementById('accuracy');
    var result_precision = document.getElementById('precision');
    var result_recall = document.getElementById('recall');

    var i_accuracy_down = document.getElementById('i-accuracy-down');
    var i_accuracy_up = document.getElementById('i-accuracy-up');
    var i_precision_down = document.getElementById('i-precision-down');
    var i_precision_up = document.getElementById('i-precision-up');
    var i_recall_down = document.getElementById('i-recall-down');
    var i_recall_up = document.getElementById('i-recall-up');

    // 设置fetch的选项
    var fetchOptions = {
        method: 'POST',
        body: formData,
        credentials: 'include', // 确保cookies（包括CSRF令牌）被包含在请求中
        headers: {
            'X-CSRFToken': csrftoken // 将CSRF令牌添加到请求头
        }
    };

    // 使用fetch API发送AJAX请求
    fetch(document.getElementById('tuningForm').action, fetchOptions)
    .then(response => response.json())
    .then(data => {
        console.log(data);
        // 处理服务器响应的数据
        // 返回的数据上传
        if (data.status === 'success') {
            // 恢复点击按钮
            submitButton.style.backgroundColor = '';
            submitButton.disabled = false;
            submitButton.textContent = '确认并开始训练';
            console.log('该模型的准确率为：', data.accuracy);
            Loading.style.display = 'none';
            console.log('数据:', result_accuracy.innerText.replace('%', ''));
            // 根据上次结果显示箭头的方向
            if (data.accuracy > result_accuracy.innerText.replace('%', '')){
                i_accuracy_down.style.display = 'none';
                i_accuracy_up.style.display = 'block';
            }else {
                i_accuracy_up.style.display = 'none';
                i_accuracy_down.style.display = 'block';
            }

            if (data.precision > result_precision.innerText.replace('%', '')){
                i_precision_down.style.display = 'none';
                i_precision_up.style.display = 'block';
            }else {
                i_precision_up.style.display = 'none';
                i_precision_down.style.display = 'block';
            }

            if (data.recall > result_recall.innerText.replace('%', '')){
                i_recall_down.style.display = 'none';
                i_recall_up.style.display = 'block';
            }else {
                i_recall_up.style.display = 'none';
                i_recall_down.style.display = 'block';
            }
            // 显示结果
            tuning_result.style.display = 'block';
            result_accuracy.style.width = data.accuracy + '%';
            result_accuracy.innerText = data.accuracy + '%';

            result_precision.style.width = data.precision + '%';
            result_precision.innerText = data.precision + '%';

            result_recall.style.width = data.recall + '%';
            result_recall.innerText = data.recall + '%';
        }
        else{
            console.log('训练失败！！！');
        }

    })
    .catch(error => {
        console.error('Error:', error);
    });
}




