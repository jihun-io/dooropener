document.addEventListener('click', function(event) {
    var target = event.target;
    while (target && target.tagName !== 'A') {
        target = target.parentNode;
    }
    if (target && target.href) {
        event.preventDefault();
        window.location = target.href;
    }
}, false);
