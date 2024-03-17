// Check if the page is loaded in an iframe
if (window.self !== window.top) {
  // The page is loaded in an iframe

  // Add CSS to disable text selection for all elements except input and textarea
  var style = document.createElement('style');
  style.type = 'text/css';
  style.innerHTML = `
  * {
      -webkit-user-select: none;  /* Chrome, Safari, Opera */
      -moz-user-select: none;     /* Firefox */
      -ms-user-select: none;      /* IE 10+ */
      user-select: none;          /* Standard syntax */
  }
  input, textarea {
      -webkit-user-select: auto;  /* Chrome, Safari, Opera */
      -moz-user-select: auto;     /* Firefox */
      -ms-user-select: auto;      /* IE 10+ */
      user-select: auto;          /* Standard syntax */
  }`;
  document.head.appendChild(style);

  // Add event listener to the document to blur input when clicked outside
  document.addEventListener('click', function (event) {
    var isClickInsideInput = event.target.tagName === 'INPUT' || event.target.tagName === 'TEXTAREA';
    var isClickInsideLinkOrButton = event.target.tagName === 'A' || event.target.tagName === 'BUTTON';

    if (!isClickInsideInput && !isClickInsideLinkOrButton) {
      document.activeElement.blur();
    }
  });
} else {
  // The page is not loaded in an iframe

  // Add CSS to enable text selection for all elements
  var style = document.createElement('style');
  style.type = 'text/css';
  style.innerHTML = `
  * {
      -webkit-user-select: auto;  /* Chrome, Safari, Opera */
      -moz-user-select: auto;     /* Firefox */
      -ms-user-select: auto;      /* IE 10+ */
      user-select: auto;          /* Standard syntax */
  }`;
  document.head.appendChild(style);
}