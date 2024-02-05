// Add custom scripts 
function updatePasswordStrength(password) {
    const strengthMeter = document.getElementById('passwordStrength');

    // Use zxcvbn to assess password strength
    const result = zxcvbn(password);

    // Get the strength score from zxcvbn result (0 to 4)
    const score = result.score;

    // Define strength levels based on zxcvbn score
    let strength;
    let color;

    switch (score) {
        case 0:
            strength = 'Very Weak';
            color = 'red';
            break;
        case 1:
            strength = 'Weak';
            color = 'orange';
            break;
        case 2:
            strength = 'Moderate';
            color = '#FFCC00'; // Darker yellow color
            break;
        case 3:
            strength = 'Strong';
            color = 'green';
            break;
        case 4:
            strength = 'Very Strong';
            color = 'darkgreen';
            break;
        default:
            strength = 'Unknown';
            color = 'black';
    }

    // Update the strength meter display and text color
    strengthMeter.textContent = strength;
    strengthMeter.style.color = color;
}


function togglePasswordField() {
    const passwordField = document.getElementById('password');
    const toggleIcon = document.getElementById('togglePassword');

    if (passwordField.type === 'password') {
        passwordField.type = 'text';
        toggleIcon.textContent = 'Hide Password';
    } else {
        passwordField.type = 'password';
        toggleIcon.textContent = 'Show Password';
    }
}

function preventConsecutiveSpaces(passwordField) {
    const currentValue = passwordField.value;

    // Replace consecutive spaces with a single space
    const sanitizedValue = currentValue.replace(/ {2,}/g, ' ');

    // Update the password field value
    passwordField.value = sanitizedValue;
}

function is_confirmed() {
    const new_passwordField = document.getElementById('new_password');
    const confirm_passwordField = document.getElementById('confirm_password');
    
    const new_password = new_passwordField.value;
    const confirm_password = confirm_passwordField.value;
    if(new_password == confirm_password)
        updatePasswordStrength(new_password);
}


async function checkBreach(password) {
    const sha1Hash = sha1(password); // Hash the password (using a hashing library like js-sha1)

    const prefix = sha1Hash.substring(0, 5); // Take the first 5 characters of the hash as the prefix
    const suffix = sha1Hash.substring(5); // Take the remaining characters as the suffix

    try {
        const response = await fetch(`https://api.pwnedpasswords.com/range/${prefix}`);
        const data = await response.text();

        // Check if the suffix exists in the response
        const match = data.split('\n').find(line => line.startsWith(suffix.toUpperCase()));

        if (match) {
            // Show breach warning popup
            document.getElementById('p_error').textContent = 'This password has been breached. You can change it in your profile.';
        }
        else{
            document.getElementById('p_error').textContent = '';
        }
    } catch (error) {
        console.error('Error checking breach:', error);
        // Handle errors, e.g., show a generic error message
    }
}

// Function to hash the password using SHA-1 (replace with a secure hashing library)
function sha1(input) {
    // Implement your secure hashing logic here
    // This example uses a simplified approach and should be replaced with a secure hashing function
    return CryptoJS.SHA1(input).toString();
}
