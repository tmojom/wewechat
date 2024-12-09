document.addEventListener('DOMContentLoaded', () => {
    const container = document.getElementById('container');
    const signUpBtn = document.querySelector('.toggle-btn');
    const backToLoginBtn = document.querySelector('.back-to-login');
    
    signUpBtn.addEventListener('click', () => {
        container.classList.add("right-panel-active");
    });

    backToLoginBtn.addEventListener('click', () => {
        container.classList.remove("right-panel-active");
    });
});

function validatePassword(password, username) {
    // 密码长度至少8位
    if (password.length < 8) return false;
    
    // 检查是否包含大写字母
    if (!/[A-Z]/.test(password)) return false;
    
    // 检查是否包含小写字母
    if (!/[a-z]/.test(password)) return false;
    
    // 检查是否包含数字
    if (!/[0-9]/.test(password)) return false;
    
    // 检查是否包含特殊字符
    if (!/[!@#$%^&*(),.?":{}|<>]/.test(password)) return false;
    
    // 检查是否与用户名相同
    if (password.toLowerCase().includes(username.toLowerCase())) return false;
    
    return true;
}

async function handleLogin(event) {
    event.preventDefault();
    
    const phone = document.getElementById('loginPhone').value;
    const password = document.getElementById('loginPassword').value;

    // 验证手机号格式
    if (!/^1[3-9]\d{9}$/.test(phone)) {
        alert('请输入正确的手机号码');
        return false;
    }

    try {
        const response = await fetch('http://localhost:3001/login', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({ phone, password })
        });

        const data = await response.json();
        if (data.success) {
            sessionStorage.setItem('username', data.username);
            sessionStorage.setItem('avatarUrl', data.avatarUrl);
            window.location.href = '/chat.html';
            return false;
        }
        alert(data.message);
    } catch (error) {
        console.error('登录错误:', error);
        alert('登录失败，请重试');
    }
    return false;
}

async function handleRegister(event) {
    event.preventDefault();
    
    const username = document.getElementById('registerUsername').value;
    const phone = document.getElementById('registerPhone').value;
    const password = document.getElementById('registerPassword').value;

    // 验证手机号格式
    if (!/^1[3-9]\d{9}$/.test(phone)) {
        alert('请输入正确的手机号码');
        return false;
    }

    // 验证密码复杂度
    if (!validatePassword(password, username)) {
        alert('密码必须包含大小写字母、数字和特殊字符，且不能包含用户名');
        return false;
    }

    try {
        const response = await fetch('http://localhost:3001/register', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({ username, phone, password })
        });

        const data = await response.json();
        alert(data.message);
        if (data.success) {
            sessionStorage.setItem('username', data.username);
            sessionStorage.setItem('avatarUrl', data.avatarUrl);
            document.getElementById('container').classList.remove('right-panel-active');
            document.getElementById('registerForm').reset();
        }
    } catch (error) {
        console.error('注册错误:', error);
        alert('注册失败，请重试');
    }
    return false;
} 