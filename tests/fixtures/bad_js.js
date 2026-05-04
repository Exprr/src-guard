// Bad JS file
const secret = "A9z-8k2-Lp0-Qx7"; // High entropy
const fake = "token_value"; // Low entropy

eval("alert(1)"); // Medium
document.write("XSS"); // Medium
document.getElementById("app").innerHTML = "unsafe"; // Medium
