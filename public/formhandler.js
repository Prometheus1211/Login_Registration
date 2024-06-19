
document.addEventListener('DOMContentLoaded', function() {
    // Function to handle login form submission
    document.getElementById('loginForm').addEventListener('submit', async function(event) {
      event.preventDefault();
  
      const username = document.getElementById('loginUsername').value;
      const password = document.getElementById('loginPassword').value;
  
      try {
        const response = await fetch('/login', {
          method: 'POST',
          headers: {
            'Content-Type': 'application/json'
          },
          body: JSON.stringify({ username, password })
        });
  
        if (response.redirected) {
          window.location.href = response.url;
        } else if (response.ok) {
          // Reset error message
          document.getElementById('errorMessage').textContent = '';
        } else if (response.status === 401) {
          // Display error message for invalid username or password
          document.getElementById('errorMessage').textContent = 'Invalid username or password';
        } else {
          // Handle other error cases
          const data = await response.json();
          document.getElementById('errorMessage').textContent = data.error;
        }
      } catch (error) {
        console.error('Error during login:', error);
        document.getElementById('errorMessage').textContent = 'Internal server error';
      }
    });
  
    // Function to handle signup form submission
    function isValidUsername(username) {
      // Regex pattern to allow alphanumeric characters and underscores
      const usernameRegex = /^[a-zA-Z0-9_]+$/;
      return usernameRegex.test(username);
    }
  
    // Function to validate password with at least one special character using regex
    function isValidPassword(password) {
      // Regex pattern to allow at least one special character
      const passwordRegex = /[!@#$%^&*()_+\-=\[\]{};':"\\|,.<>\/?]+/;
      return passwordRegex.test(password);
    }
  
    document.getElementById("signupForm").addEventListener("submit", async function(event) {
      event.preventDefault();
      const username = document.getElementById("signupUsername").value;
      const password = document.getElementById("signupPassword").value;
  
      // Validate username and password
      if (!isValidUsername(username)) {
        alert("Invalid username. Username must contain only alphanumeric characters and underscores.");
        return;
      }
      if (!isValidPassword(password)) {
        alert("Invalid password. Password must contain at least one special character.");
        return;
      }
  
      // Make registration request
      try {
        const response = await fetch('/register', {
          method: 'POST',
          headers: {
            'Content-Type': 'application/json'
          },
          body: JSON.stringify({ username, password })
        });
  
        // Check if registration was successful
        if (response.ok) {
          const responseData = await response.json();
          if (responseData.success) {
            alert("Registration successful. Please log in."); // Display success message
            // Redirect to login page after successful registration
            window.location.href = "index.html";
          } else {
            alert(responseData.message); // Display error message
          }
        } else if (response.status === 400) {
          const responseData = await response.json();
          alert(responseData.message); // Display error message for duplicate username
        } else {
          alert("Registration failed. Please try again."); // Display generic error message
        }
      } catch (error) {
        alert("Registration failed. Please try again."); // Display error message
        console.error("Error during registration:", error);
      }
    });
  });
  