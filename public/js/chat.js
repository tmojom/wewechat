// 添加消息类型支持
function sendMessage(type, content) {
    const message = {
        type: type, // text, image, file, voice 等
        content: content,
        sender: currentUser,
        receiver: selectedContact,
        timestamp: new Date()
    };
    
    socket.emit('private_message', message);
    appendMessage(message);
}

// 添加文件上传功能
function handleFileUpload(event) {
    const file = event.target.files[0];
    const reader = new FileReader();
    
    reader.onload = function(e) {
        sendMessage('file', {
            name: file.name,
            type: file.type,
            size: file.size,
            data: e.target.result
        });
    };
    reader.readAsDataURL(file);
}

// 添加桌面通知支持
function enableNotifications() {
    if (!("Notification" in window)) {
        alert("此浏览器不支持通知功能");
        return;
    }

    Notification.requestPermission().then(function(permission) {
        if (permission === "granted") {
            setupMessageNotifications();
        }
    });
}

function showNotification(message) {
    if (Notification.permission === "granted" && document.hidden) {
        new Notification("新消息", {
            body: `${message.sender}: ${message.content}`,
            icon: "/images/icon/notification-icon.png"
        });
    }
} 

// 打开修改密码对话框
function openChangePasswordDialog() {
    document.getElementById('change-password-dialog').style.display = 'flex';
}

// 关闭修改密码对话框
function closeChangePasswordDialog() {
    document.getElementById('change-password-dialog').style.display = 'none';
    // 清空输入框
    document.getElementById('current-password').value = '';
    document.getElementById('new-password').value = '';
    document.getElementById('confirm-password').value = '';
}

// 修改密码
async function changePassword() {
    const currentPassword = document.getElementById('current-password').value;
    const newPassword = document.getElementById('new-password').value;
    const confirmPassword = document.getElementById('confirm-password').value;

    // 验证输入
    if (!currentPassword || !newPassword || !confirmPassword) {
        alert('请填写所有密码字段');
        return;
    }

    if (newPassword !== confirmPassword) {
        alert('新密码与确认密码不匹配');
        return;
    }

    try {
        const response = await fetch('/api/change-password', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({
                currentPassword,
                newPassword
            })
        });

        const data = await response.json();

        if (response.ok) {
            alert('密码修改成功！');
            closeChangePasswordDialog();
        } else {
            alert(data.message || '密码修改失败');
        }
    } catch (error) {
        console.error('修改密码时出错:', error);
        alert('修改密码失败，请稍后重试');
    }
}