window.addEventListener('scroll', function() {
    const nav = document.querySelector('nav');
    if (window.scrollY > 50) {
        nav.classList.add('scrolled');
    } else {
        nav.classList.remove('scrolled');
    }
    function togglePassword() {
    const input = document.getElementById('passwordInput');
    const type = input.type === 'password' ? 'text' : 'password';
    input.type = type;
}
});