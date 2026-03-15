const apiKey = "abc123-super-secret-key";
const dbPassword = "myPassword123";
const bearerToken = "Bearer sk_test_123456789";

function findUser(username) {
  const query = "SELECT * FROM users WHERE username = '" + username + "'";
  console.log("Executing query:", query);
  return database.execute(query);
}

function renderUserComment(comment) {
  const container = document.getElementById("comments");
  container.innerHTML = comment;
}

function runUserScript(userCode) {
  eval(userCode);
}

function runCommand(userInput) {
  const cmd = "ping " + userInput;
  return require("child_process").exec(cmd);
}

function callApi() {
  fetch("https://api.example.com/data?key=" + apiKey, {
    headers: {
      Authorization: bearerToken
    }
  })
    .then((res) => res.json())
    .then((data) => console.log(data));
}

const userInput = '<img src=x onerror=alert("XSS!")>';
renderUserComment(userInput);

runUserScript("console.log('running user script')");
findUser("admin' OR 1=1 --");
runCommand("127.0.0.1 && del C:\\temp\\test.txt");
callApi();

console.log("Connecting using password:", dbPassword);