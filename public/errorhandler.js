// Function to parse URL query parameters
function getQueryParam(param) {
    const urlParams = new URLSearchParams(window.location.search);
    return urlParams.get(param);
}

// Display error message if unauthorized error exists
const unauthorizedError = getQueryParam('error');
if (unauthorizedError) {
    document.getElementById('errorMessage').textContent = unauthorizedError;
}
